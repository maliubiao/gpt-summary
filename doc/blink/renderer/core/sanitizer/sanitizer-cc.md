Response:
Let's break down the thought process for analyzing the `sanitizer.cc` file.

1. **Understand the Goal:** The core purpose of this file is to implement a sanitizer. Sanitizers generally take potentially unsafe content (like HTML) and process it to remove or modify elements and attributes deemed dangerous or unwanted.

2. **Identify Key Classes and Structures:**  The code uses a `Sanitizer` class as its primary component. It also interacts with several other classes/structures, notably:
    * `SanitizerConfig`:  This likely holds the configuration for the sanitizer, specifying allowed/removed elements and attributes.
    * V8 Binding Classes (`V8SanitizerAttributeNamespace`, `V8SanitizerConfig`, etc.): These are bridges between C++ and JavaScript, allowing JavaScript to configure the sanitizer. The presence of "V8" strongly indicates this interaction.
    * DOM Classes (`Element`, `Node`, `ContainerNode`):  These are the standard Blink DOM objects that the sanitizer operates on.
    * `QualifiedName`:  Represents an element or attribute name, including its namespace.
    * `HashSet`, `HeapVector`: Standard C++ data structures used to store collections of names.

3. **Analyze the `Sanitizer` Class:**  Examine the member variables and methods of the `Sanitizer` class:
    * **Member Variables:** The member variables clearly indicate what the sanitizer keeps track of: allowed/removed/replaced elements, allowed/removed attributes (globally and per-element), whether `data-` attributes are allowed, and whether comments are allowed. This gives a high-level overview of the sanitizer's capabilities.
    * **`Create` Method:**  This is the factory method for creating `Sanitizer` instances. It takes a `SanitizerConfig` and sets up the sanitizer based on that configuration. The comments about future error handling are important.
    * **Constructors:** The constructors initialize the sanitizer's state. The second constructor taking individual sets of names is likely used internally.
    * **`allowElement`, `removeElement`, `replaceWithChildrenElement`, `allowAttribute`, `removeAttribute`, `setComments`, `setDataAttributes`:** These methods provide a direct API for modifying the sanitizer's configuration programmatically. The use of V8 union types in the parameters signals the interaction with JavaScript.
    * **`removeUnsafe`:** This method uses a baseline configuration (likely a predefined set of unsafe elements/attributes) to further restrict the sanitizer. The checks using `CHECK()` are important for internal consistency.
    * **`get`:** This method seems to serialize the current sanitizer configuration back into a `SanitizerConfig` object, likely for passing it back to JavaScript or for other purposes.
    * **`AllowElement`, `RemoveElement`, `ReplaceElement`, `AllowAttribute`, `RemoveAttribute`:** These are the internal methods that directly modify the sets of allowed/removed/replaced items. They are called by the public `allowElement`, etc., methods.
    * **`SanitizeElement`:** This method processes a single `Element` and removes attributes based on the sanitizer's configuration. The logic for handling per-element attributes and `data-` attributes is crucial here.
    * **`SanitizeSafe` and `SanitizeUnsafe`:** These are the core sanitization methods. `SanitizeSafe` creates a copy and applies `removeUnsafe`, suggesting a stricter sanitization mode. `SanitizeUnsafe` iterates through the DOM tree and applies the configured rules.
    * **`setFrom` (both versions):** These methods are responsible for loading the sanitizer's configuration, either from a `SanitizerConfig` object or from another `Sanitizer` instance.
    * **`getFrom` methods:** These utility methods convert various input types (strings, V8 objects) into `QualifiedName` objects. The default namespace for unqualified element names is important to note.

4. **Identify Connections to JavaScript, HTML, and CSS:**
    * **JavaScript:** The "V8" in the parameter types of many methods clearly indicates interaction with JavaScript. The `Create` method taking a `SanitizerConfig` which is likely created in JavaScript confirms this. The `get` method returning a `SanitizerConfig` that can be passed back to JavaScript solidifies this connection.
    * **HTML:** The sanitizer operates directly on DOM elements and attributes, which are the fundamental building blocks of HTML. The examples of allowing/removing tags and attributes are direct HTML manipulations.
    * **CSS:**  While the code doesn't directly manipulate CSS *properties*, it operates on HTML *attributes* that can influence CSS styling (e.g., `class`, `style`). By removing or modifying these attributes, the sanitizer indirectly affects the rendered appearance dictated by CSS.

5. **Infer Logic and Provide Examples:** Based on the identified functionalities, devise hypothetical input and output scenarios. For example, demonstrate how allowing/removing an element or attribute would change the resulting sanitized HTML. Consider cases with per-element attributes.

6. **Identify Potential User/Programming Errors:** Think about how someone using this sanitizer might misuse it or encounter common issues. Examples include:
    * Incorrectly configuring the sanitizer (e.g., allowing unsafe attributes).
    * Not understanding the difference between `SanitizeSafe` and `SanitizeUnsafe`.
    * Assuming the sanitizer handles all possible threats (it's a configuration-based tool).

7. **Structure the Answer:** Organize the findings into logical sections like "Functionality," "Relationship with JavaScript/HTML/CSS," "Logic Inference," and "Common Errors."  Use clear and concise language. Provide code snippets where helpful.

8. **Review and Refine:**  Read through the generated analysis to ensure accuracy, clarity, and completeness. Double-check the interpretation of the code and the examples provided. For example, initially, I might have overlooked the nuance of the per-element attribute handling. A second pass would catch this. Also, ensure the language is accessible to someone who might not be an expert in Blink internals.
这个 `sanitizer.cc` 文件实现了 Chromium Blink 引擎中的一个 HTML 内容清理器（Sanitizer）。它的主要功能是接收一段 HTML 代码，并根据预先设定的规则，移除或修改其中可能存在的恶意或不安全的元素和属性，从而确保页面的安全性和符合预期的结构。

下面是它的主要功能以及与 JavaScript, HTML, CSS 的关系，逻辑推理和常见错误：

**主要功能:**

1. **创建 Sanitizer 实例:**
   - 提供 `Sanitizer::Create` 静态方法，用于根据 `SanitizerConfig` 对象创建一个 `Sanitizer` 实例。`SanitizerConfig` 包含了清理规则，例如允许的元素、移除的元素、允许的属性等等。

2. **配置清理规则:**
   - 提供一系列方法来动态地设置或修改清理规则：
     - `allowElement`: 允许指定的元素。
     - `removeElement`: 移除指定的元素。
     - `replaceWithChildrenElement`: 将指定的元素替换为其子元素。
     - `allowAttribute`: 允许指定的属性。
     - `removeAttribute`: 移除指定的属性。
     - `setComments`: 设置是否允许保留注释。
     - `setDataAttributes`: 设置是否允许保留 `data-*` 属性。
     - 针对特定元素配置允许或移除的属性 (`allow_attrs_per_element_`, `remove_attrs_per_element_`)。

3. **移除不安全内容:**
   - `removeUnsafe` 方法：根据预定义的“baseline”配置（通常包含已知的不安全元素和属性），移除这些不安全的内容。这个方法依赖于 `SanitizerBuiltins::GetBaseline()` 提供基线配置。

4. **获取当前配置:**
   - `get` 方法：返回一个包含当前 Sanitizer 配置的 `SanitizerConfig` 对象。

5. **执行清理操作:**
   - `SanitizeElement`: 清理单个 `Element` 节点的属性，移除未被允许的属性。
   - `SanitizeSafe`: 执行安全的清理操作，会先复制当前的 Sanitizer 配置，然后应用 `removeUnsafe` 方法，再执行不安全的清理。
   - `SanitizeUnsafe`: 执行不安全的清理操作，遍历 DOM 树，根据配置移除或替换元素，并调用 `SanitizeElement` 清理元素的属性。

6. **从配置对象或另一个 Sanitizer 实例设置配置:**
   - `setFrom(const SanitizerConfig* config)`: 从 `SanitizerConfig` 对象加载清理规则。
   - `setFrom(const Sanitizer& other)`: 从另一个 `Sanitizer` 实例复制清理规则。

7. **辅助方法:**
   - `getFrom`: 一系列重载方法，用于从不同类型的输入（字符串、V8 对象）获取 `QualifiedName` 对象，方便处理元素和属性名称。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - **配置:** `Sanitizer` 的配置通常由 JavaScript 代码通过 Web API (可能与 `SanitizerConfig` 相关) 进行设置。例如，JavaScript 可以创建一个 `SanitizerConfig` 对象，设置允许的标签和属性，然后传递给 `Sanitizer.Create` 方法。
    - **V8 绑定:** 文件中包含了大量的 V8 绑定相关的头文件，例如 `v8_sanitizer_attribute_namespace.h` 等，这表明 `Sanitizer` 的配置可以通过 JavaScript 直接操作。`SanitizerConfig` 和相关的类很可能暴露给了 JavaScript，使得 JavaScript 可以创建和修改这些配置对象。
    - **示例:** 假设 JavaScript 代码想要创建一个只允许 `p` 标签和 `class` 属性的 Sanitizer：
      ```javascript
      const config = new SanitizerConfig();
      config.elements = [{ name: "p" }];
      config.attributes = [{ name: "class" }];
      const sanitizer = Sanitizer.create(config);
      // 然后可以使用 sanitizer 清理 HTML 内容
      ```

* **HTML:**
    - **核心功能:** `Sanitizer` 的主要作用就是处理 HTML 内容。它接收包含 HTML 结构的 DOM 树作为输入，并根据配置修改这个 DOM 树，移除或修改元素和属性。
    - **元素和属性处理:**  `Sanitizer` 的各种方法直接操作 HTML 的元素（例如 `allowElement("div")`）和属性（例如 `allowAttribute("href")`）。
    - **示例:** 假设输入的 HTML 代码是 `<div class="container"><script>alert('evil')</script><p>Hello</p></div>`，并且 Sanitizer 的配置只允许 `p` 标签和 `class` 属性。清理后的输出可能变成 `<div class="container"><p>Hello</p></div>`，移除了 `<script>` 标签。

* **CSS:**
    - **间接影响:** `Sanitizer` 本身不直接解析或修改 CSS 代码。但是，它通过移除或修改 HTML 元素和属性，可以间接地影响页面的样式。
    - **移除样式相关的属性:** 例如，如果 Sanitizer 配置移除了 `style` 属性，那么元素上的内联样式将会丢失。同样，移除 `class` 或 `id` 属性可能会影响 CSS 选择器的匹配，从而改变元素的样式。
    - **示例:** 如果输入的 HTML 是 `<p style="color: red;" class="important">Text</p>`，而 Sanitizer 配置移除了 `style` 属性，清理后会变成 `<p class="important">Text</p>`，元素的颜色样式丢失。

**逻辑推理 (假设输入与输出):**

**假设输入:**

```html
<div id="outer">
  <span data-custom="info">Some text</span>
  <a href="javascript:void(0)">Click me</a>
  <img src="evil.jpg" onerror="alert('bad')">
  <!-- This is a comment -->
</div>
```

**场景 1:  Sanitizer 配置为允许 `div`, `span`, `a` 元素，允许 `id`, `data-*` 属性，移除 `href` 属性中的 `javascript:`，不允许 `img` 元素和 `onerror` 属性，允许注释。**

**清理后的输出:**

```html
<div id="outer">
  <span data-custom="info">Some text</span>
  <a>Click me</a>
  <!-- This is a comment -->
</div>
```

**推理:**
- `div` 和 `span` 元素被保留，因为它们在允许列表中。
- `a` 元素被保留，但 `href` 属性中如果包含 `javascript:` 协议，可能会被移除（虽然代码中没有明确看到 `href` 内容的清理逻辑，但通常 Sanitizer 会处理此类问题）。假设这里移除了 `href` 属性或仅保留了安全的 URL。
- `img` 元素被移除，因为它不在允许列表中。
- `onerror` 属性被移除，因为它不在允许列表中。
- `id` 和 `data-custom` 属性被保留，因为它们在允许列表中。
- 注释被保留，因为配置允许注释。

**场景 2: Sanitizer 配置为移除 `span` 元素，并将 `div` 替换为其子元素。**

**清理后的输出:**

```html
  Some text
  <a href="javascript:void(0)">Click me</a>
  <img src="evil.jpg" onerror="alert('bad')">
  <!-- This is a comment -->
```

**推理:**
- `div` 元素被移除，其子元素被提升到其父元素的位置。
- `span` 元素被移除。
- 其他元素和属性的处理取决于配置中对它们的具体规则。

**涉及用户或者编程常见的使用错误:**

1. **配置不足或过于宽松:**
   - **错误:** 用户或开发者在配置 `Sanitizer` 时，可能没有考虑到所有可能的攻击向量，导致某些不安全的元素或属性被意外地允许。
   - **示例:** 允许所有的 `data-*` 属性，但没有意识到某些自定义的 JavaScript 代码可能会利用特定的 `data-*` 属性执行恶意操作。

2. **配置过于严格:**
   - **错误:**  过度限制允许的元素和属性，导致正常的、合法的 HTML 结构被破坏，页面功能受损。
   - **示例:** 移除所有 `style` 属性，导致页面上的所有内联样式丢失，页面可能变得难以阅读。

3. **不理解 `SanitizeSafe` 和 `SanitizeUnsafe` 的区别:**
   - **错误:**  错误地使用了 `SanitizeUnsafe` 方法，认为它和 `SanitizeSafe` 一样安全。`SanitizeUnsafe` 不会应用预定义的“baseline”安全规则，可能留下潜在的风险。
   - **示例:**  开发者直接使用 `SanitizeUnsafe` 清理用户输入，而没有意识到这可能会跳过一些重要的安全检查。

4. **错误地配置了 per-element 的属性规则:**
   - **错误:**  在为特定元素配置允许或移除的属性时出现错误，例如拼写错误或者逻辑错误。
   - **示例:** 想要允许 `<img data-src="...">`，但错误地配置成了允许 `<image data-src="...">`，导致 `<img>` 标签的 `data-src` 属性被错误地移除。

5. **没有及时更新 Sanitizer 的配置:**
   - **错误:**  随着新的攻击方式出现，旧的 Sanitizer 配置可能无法有效地阻止这些攻击。
   - **示例:**  新的 XSS 攻击技巧利用了之前未被考虑的 HTML 标签或属性，而 Sanitizer 的配置没有及时更新，导致攻击成功。

6. **过度依赖客户端 Sanitizer:**
   - **错误:**  仅在客户端进行 HTML 清理，而没有在服务器端进行二次验证或清理。客户端的 Sanitizer 可以被绕过或禁用，因此服务器端的安全措施至关重要。

总而言之，`sanitizer.cc` 文件实现了 Blink 引擎中的 HTML 内容清理功能，它与 JavaScript 通过配置进行交互，处理 HTML 结构，并间接地影响 CSS 样式。正确配置和使用 Sanitizer 是确保 Web 应用安全的重要环节，但用户和开发者需要避免常见的配置错误和理解其局限性。

### 提示词
```
这是目录为blink/renderer/core/sanitizer/sanitizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/sanitizer/sanitizer.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_sanitizer_attribute_namespace.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_sanitizer_config.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_sanitizer_element_namespace.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_sanitizer_element_namespace_with_attributes.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_sanitizerattributenamespace_string.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_sanitizerelementnamespace_string.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_sanitizerelementnamespacewithattributes_string.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer_builtins.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

Sanitizer* Sanitizer::Create(const SanitizerConfig* sanitizer_config,
                             ExceptionState& exception_state) {
  Sanitizer* sanitizer = MakeGarbageCollected<Sanitizer>();
  if (!sanitizer_config) {
    NOTREACHED();  // Default handling not yet implemented.
  }
  if (!sanitizer->setFrom(sanitizer_config)) {
    // As currently implemented, all inputs will lead to successful creation
    // of a Sanitizer instance. But the current spec discussion aims to
    // introduce invalid configurations. Once we implement that, this will be
    // replaced with `exception_state.ThrowTypeError(...); return nullptr;`.
    NOTREACHED();
  }
  return sanitizer;
}

Sanitizer::Sanitizer(HashSet<QualifiedName> allow_elements,
                     HashSet<QualifiedName> remove_elements,
                     HashSet<QualifiedName> replace_elements,
                     HashSet<QualifiedName> allow_attrs,
                     HashSet<QualifiedName> remove_attrs,
                     bool allow_data_attrs,
                     bool allow_comments)
    : allow_elements_(allow_elements.begin(), allow_elements.end()),
      remove_elements_(remove_elements.begin(), remove_elements.end()),
      replace_elements_(replace_elements.begin(), replace_elements.end()),
      allow_attrs_(allow_attrs.begin(), allow_attrs.end()),
      remove_attrs_(remove_attrs.begin(), remove_attrs.end()),
      allow_data_attrs_(allow_data_attrs),
      allow_comments_(allow_comments) {}

void Sanitizer::allowElement(
    const V8UnionSanitizerElementNamespaceWithAttributesOrString* element) {
  const QualifiedName name = getFrom(element);
  AllowElement(name);

  // The internal AllowElement doesn't handle per-element attrs (yet).
  if (element->IsSanitizerElementNamespaceWithAttributes()) {
    const SanitizerElementNamespaceWithAttributes* element_with_attrs =
        element->GetAsSanitizerElementNamespaceWithAttributes();
    if (element_with_attrs->hasAttributes()) {
      const auto add_result =
          allow_attrs_per_element_.insert(name, SanitizerNameSet());
      for (const auto& attr : element_with_attrs->attributes()) {
        add_result.stored_value->value.insert(getFrom(attr));
      }
    }
    if (element_with_attrs->hasRemoveAttributes()) {
      const auto add_result =
          remove_attrs_per_element_.insert(name, SanitizerNameSet());
      for (const auto& attr : element_with_attrs->removeAttributes()) {
        add_result.stored_value->value.insert(getFrom(attr));
      }
    }
  }
}

void Sanitizer::removeElement(
    const V8UnionSanitizerElementNamespaceOrString* element) {
  RemoveElement(getFrom(element));
}

void Sanitizer::replaceWithChildrenElement(
    const V8UnionSanitizerElementNamespaceOrString* element) {
  ReplaceElement(getFrom(element));
}

void Sanitizer::allowAttribute(
    const V8UnionSanitizerAttributeNamespaceOrString* attribute) {
  AllowAttribute(getFrom(attribute));
}

void Sanitizer::removeAttribute(
    const V8UnionSanitizerAttributeNamespaceOrString* attribute) {
  RemoveAttribute(getFrom(attribute));
}

void Sanitizer::setComments(bool comments) {
  allow_comments_ = comments;
}

void Sanitizer::setDataAttributes(bool data_attributes) {
  allow_data_attrs_ = data_attributes;
}

void Sanitizer::removeUnsafe() {
  const Sanitizer* baseline = SanitizerBuiltins::GetBaseline();

  // Below, we rely on the baseline being expressed as allow-lists. Ensure that
  // this is so, given how important `removeUnsafe` is for the Sanitizer.
  CHECK(!baseline->remove_elements_.empty());
  CHECK(!baseline->remove_attrs_.empty());
  CHECK(baseline->allow_elements_.empty());
  CHECK(baseline->replace_elements_.empty());
  CHECK(baseline->allow_attrs_.empty());
  CHECK(baseline->replace_elements_.empty());
  CHECK(baseline->allow_attrs_per_element_.empty());
  CHECK(baseline->remove_attrs_per_element_.empty());

  for (const QualifiedName& name : baseline->remove_elements_) {
    RemoveElement(name);
  }
  for (const QualifiedName& name : baseline->remove_attrs_) {
    RemoveAttribute(name);
  }
}

SanitizerConfig* Sanitizer::get() const {
  HeapVector<Member<V8UnionSanitizerElementNamespaceWithAttributesOrString>>
      allow_elements;
  for (const QualifiedName& name : allow_elements_) {
    Member<SanitizerElementNamespaceWithAttributes> element =
        SanitizerElementNamespaceWithAttributes::Create();
    element->setName(name.LocalName());
    element->setNamespaceURI(name.NamespaceURI());

    const auto& allow_attrs_per_element_iter =
        allow_attrs_per_element_.find(name);
    if (allow_attrs_per_element_iter != allow_attrs_per_element_.end()) {
      HeapVector<Member<V8UnionSanitizerAttributeNamespaceOrString>>
          allow_attrs_per_element;
      for (const QualifiedName& attr_name :
           allow_attrs_per_element_iter->value) {
        Member<SanitizerAttributeNamespace> attr =
            SanitizerAttributeNamespace::Create();
        attr->setName(attr_name.LocalName());
        attr->setNamespaceURI(attr_name.NamespaceURI());
        allow_attrs_per_element.push_back(
            MakeGarbageCollected<V8UnionSanitizerAttributeNamespaceOrString>(
                attr));
      }
      element->setAttributes(allow_attrs_per_element);
    }

    const auto& remove_attrs_per_element_iter =
        remove_attrs_per_element_.find(name);
    if (remove_attrs_per_element_iter != remove_attrs_per_element_.end()) {
      HeapVector<Member<V8UnionSanitizerAttributeNamespaceOrString>>
          remove_attrs_per_element;
      for (const QualifiedName& attr_name :
           remove_attrs_per_element_iter->value) {
        Member<SanitizerAttributeNamespace> attr =
            SanitizerAttributeNamespace::Create();
        attr->setName(attr_name.LocalName());
        attr->setNamespaceURI(attr_name.NamespaceURI());
        remove_attrs_per_element.push_back(
            MakeGarbageCollected<V8UnionSanitizerAttributeNamespaceOrString>(
                attr));
      }
      element->setRemoveAttributes(remove_attrs_per_element);
    }

    allow_elements.push_back(
        MakeGarbageCollected<
            V8UnionSanitizerElementNamespaceWithAttributesOrString>(element));
  }

  HeapVector<Member<V8UnionSanitizerElementNamespaceOrString>> remove_elements;
  for (const QualifiedName& name : remove_elements_) {
    Member<SanitizerElementNamespace> element =
        SanitizerElementNamespace::Create();
    element->setName(name.LocalName());
    element->setNamespaceURI(name.NamespaceURI());
    remove_elements.push_back(
        MakeGarbageCollected<V8UnionSanitizerElementNamespaceOrString>(
            element));
  }

  HeapVector<Member<V8UnionSanitizerElementNamespaceOrString>> replace_elements;
  for (const QualifiedName& name : replace_elements_) {
    Member<SanitizerElementNamespace> element =
        SanitizerElementNamespace::Create();
    element->setName(name.LocalName());
    element->setNamespaceURI(name.NamespaceURI());
    replace_elements.push_back(
        MakeGarbageCollected<V8UnionSanitizerElementNamespaceOrString>(
            element));
  }

  HeapVector<Member<V8UnionSanitizerAttributeNamespaceOrString>> allow_attrs;
  for (const QualifiedName& name : allow_attrs_) {
    Member<SanitizerAttributeNamespace> attr =
        SanitizerAttributeNamespace::Create();
    attr->setName(name.LocalName());
    attr->setNamespaceURI(name.NamespaceURI());
    allow_attrs.push_back(
        MakeGarbageCollected<V8UnionSanitizerAttributeNamespaceOrString>(attr));
  }

  HeapVector<Member<V8UnionSanitizerAttributeNamespaceOrString>> remove_attrs;
  for (const QualifiedName& name : remove_attrs_) {
    Member<SanitizerAttributeNamespace> attr =
        SanitizerAttributeNamespace::Create();
    attr->setName(name.LocalName());
    attr->setNamespaceURI(name.NamespaceURI());
    remove_attrs.push_back(
        MakeGarbageCollected<V8UnionSanitizerAttributeNamespaceOrString>(attr));
  }

  SanitizerConfig* config = SanitizerConfig::Create();
  config->setElements(allow_elements);
  config->setRemoveElements(remove_elements);
  config->setReplaceWithChildrenElements(replace_elements);
  config->setAttributes(allow_attrs);
  config->setRemoveAttributes(remove_attrs);
  config->setDataAttributes(allow_data_attrs_);
  config->setComments(allow_comments_);

  return config;
}

void Sanitizer::AllowElement(const QualifiedName& name) {
  allow_elements_.insert(name);
  remove_elements_.erase(name);
  replace_elements_.erase(name);
  allow_attrs_per_element_.erase(name);
  remove_attrs_per_element_.erase(name);
}

void Sanitizer::RemoveElement(const QualifiedName& name) {
  allow_elements_.erase(name);
  remove_elements_.insert(name);
  replace_elements_.erase(name);
  allow_attrs_per_element_.erase(name);
  remove_attrs_per_element_.erase(name);
}

void Sanitizer::ReplaceElement(const QualifiedName& name) {
  allow_elements_.erase(name);
  remove_elements_.erase(name);
  replace_elements_.insert(name);
  allow_attrs_per_element_.erase(name);
  remove_attrs_per_element_.erase(name);
}

void Sanitizer::AllowAttribute(const QualifiedName& name) {
  allow_attrs_.insert(name);
  remove_attrs_.erase(name);
}

void Sanitizer::RemoveAttribute(const QualifiedName& name) {
  allow_attrs_.erase(name);
  remove_attrs_.insert(name);
}

void Sanitizer::SanitizeElement(Element* element) const {
  const auto allow_per_element_iter =
      allow_attrs_per_element_.find(element->TagQName());
  const SanitizerNameSet* allow_per_element =
      (allow_per_element_iter == allow_attrs_per_element_.end())
          ? nullptr
          : &allow_per_element_iter->value;
  const auto remove_per_element_iter =
      remove_attrs_per_element_.find(element->TagQName());
  const SanitizerNameSet* remove_per_element =
      (remove_per_element_iter == remove_attrs_per_element_.end())
          ? nullptr
          : &remove_per_element_iter->value;
  for (const QualifiedName& name : element->getAttributeQualifiedNames()) {
    bool keep = false;
    if (allow_attrs_.Contains(name)) {
      keep = true;
    } else if (remove_attrs_.Contains(name)) {
      keep = false;
    } else if (allow_per_element && allow_per_element->Contains(name)) {
      keep = true;
    } else if (remove_per_element && remove_per_element->Contains(name)) {
      keep = false;
    } else {
      keep = allow_attrs_.empty() &&
             (!allow_per_element || allow_per_element->empty());
      if (!keep && allow_data_attrs_ && name.NamespaceURI().IsNull() &&
          name.LocalName().StartsWith("data-")) {
        keep = true;
      }
    }
    if (!keep) {
      element->removeAttribute(name);
    }
  }
}

void Sanitizer::SanitizeSafe(Node* root) const {
  // TODO(vogelheim): This is hideously inefficient, but very easy to implement.
  // We'll use this for now, so we can fully build out tests & other
  // infrastructure, and worry about efficiency later.
  Sanitizer* safe = MakeGarbageCollected<Sanitizer>();
  safe->setFrom(*this);
  safe->removeUnsafe();
  safe->SanitizeUnsafe(root);
}

void Sanitizer::SanitizeUnsafe(Node* root) const {
  enum { kKeep, kKeepElement, kDrop, kReplaceWithChildren } action = kKeep;

  Node* node = NodeTraversal::Next(*root);
  while (node) {
    switch (node->getNodeType()) {
      case Node::NodeType::kElementNode: {
        Element* element = To<Element>(node);
        if (allow_elements_.Contains(element->TagQName())) {
          action = kKeepElement;
        } else if (replace_elements_.Contains(element->TagQName())) {
          action = kReplaceWithChildren;
        } else if (allow_elements_.empty() &&
                   !remove_elements_.Contains(element->TagQName())) {
          action = kKeepElement;
        } else {
          action = kDrop;
        }
        break;
      }
      case Node::NodeType::kTextNode:
        action = kKeep;
        break;
      case Node::NodeType::kCommentNode:
        action = allow_comments_ ? kKeep : kDrop;
        break;

      default:
        NOTREACHED();
    }

    switch (action) {
      case kKeepElement: {
        CHECK_EQ(node->getNodeType(), Node::NodeType::kElementNode);
        SanitizeElement(To<Element>(node));
        node = NodeTraversal::Next(*node);
        break;
      }
      case kKeep: {
        CHECK_NE(node->getNodeType(), Node::NodeType::kElementNode);
        node = NodeTraversal::Next(*node);
        break;
      }
      case kReplaceWithChildren: {
        CHECK_EQ(node->getNodeType(), Node::NodeType::kElementNode);
        Node* next_node = node->firstChild();
        if (!next_node) {
          next_node = NodeTraversal::Next(*node);
        }
        ContainerNode* parent = node->parentNode();
        while (Node* child = node->firstChild()) {
          parent->InsertBefore(child, node);
        }
        node->remove();
        node = next_node;
        break;
      }
      case kDrop: {
        Node* next_node = NodeTraversal::NextSkippingChildren(*node);
        node->parentNode()->removeChild(node);
        node = next_node;
        break;
      }
    }
  }
}

bool Sanitizer::setFrom(const SanitizerConfig* config) {
  // This method assumes a newly constructed instance.
  CHECK(allow_elements_.empty());
  CHECK(remove_elements_.empty());
  CHECK(replace_elements_.empty());
  CHECK(allow_attrs_.empty());
  CHECK(remove_attrs_.empty());
  CHECK(allow_attrs_per_element_.empty());
  CHECK(remove_attrs_per_element_.empty());

  if (config->hasElements()) {
    for (const auto& element : config->elements()) {
      allowElement(element);
    }
  }
  if (config->hasRemoveElements()) {
    for (const auto& element : config->removeElements()) {
      removeElement(element);
    }
  }
  if (config->hasReplaceWithChildrenElements()) {
    for (const auto& element : config->replaceWithChildrenElements()) {
      replaceWithChildrenElement(element);
    }
  }
  if (config->hasAttributes()) {
    for (const auto& attribute : config->attributes()) {
      allowAttribute(attribute);
    }
  }
  if (config->hasRemoveAttributes()) {
    for (const auto& attribute : config->removeAttributes()) {
      removeAttribute(attribute);
    }
  }
  if (config->hasComments()) {
    setComments(config->comments());
  }
  if (config->hasDataAttributes()) {
    setDataAttributes(config->dataAttributes());
  }
  return true;
}

void Sanitizer::setFrom(const Sanitizer& other) {
  allow_elements_ = other.allow_elements_;
  remove_elements_ = other.remove_elements_;
  replace_elements_ = other.replace_elements_;
  allow_attrs_ = other.allow_attrs_;
  remove_attrs_ = other.remove_attrs_;
  allow_attrs_per_element_ = other.allow_attrs_per_element_;
  remove_attrs_per_element_ = other.remove_attrs_per_element_;
  allow_data_attrs_ = other.allow_data_attrs_;
  allow_comments_ = other.allow_comments_;
}

QualifiedName Sanitizer::getFrom(const String& name,
                                 const String& namespaceURI) const {
  return QualifiedName(g_null_atom, AtomicString(name),
                       AtomicString(namespaceURI));
}

QualifiedName Sanitizer::getFrom(
    const SanitizerElementNamespace* element) const {
  CHECK(element->hasNamespaceURI());  // Declared with default.
  if (!element->hasName()) {
    return g_null_name;
  }
  return getFrom(element->name(), element->namespaceURI());
}

QualifiedName Sanitizer::getFrom(
    const V8UnionSanitizerElementNamespaceWithAttributesOrString* element)
    const {
  if (element->IsString()) {
    return getFrom(element->GetAsString(), "http://www.w3.org/1999/xhtml");
  }
  return getFrom(element->GetAsSanitizerElementNamespaceWithAttributes());
}

QualifiedName Sanitizer::getFrom(
    const V8UnionSanitizerElementNamespaceOrString* element) const {
  if (element->IsString()) {
    return getFrom(element->GetAsString(), "http://www.w3.org/1999/xhtml");
  }
  return getFrom(element->GetAsSanitizerElementNamespace());
}

QualifiedName Sanitizer::getFrom(
    const V8UnionSanitizerAttributeNamespaceOrString* attr) const {
  if (attr->IsString()) {
    return getFrom(attr->GetAsString(), g_empty_atom);
  }
  const SanitizerAttributeNamespace* attr_namespace =
      attr->GetAsSanitizerAttributeNamespace();
  if (!attr_namespace->hasName()) {
    return g_null_name;
  }
  return getFrom(attr_namespace->name(), attr_namespace->namespaceURI());
}

}  // namespace blink
```