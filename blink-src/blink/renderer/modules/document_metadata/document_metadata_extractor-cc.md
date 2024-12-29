Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The overarching goal is to analyze a Chromium source code file (`document_metadata_extractor.cc`) and explain its functionality, connections to web technologies, logic, potential errors, and debugging context.

2. **Initial Scan and Keyword Spotting:**  First, I'd quickly scan the code for recognizable keywords and patterns. This helps establish the high-level purpose.

    * `#include`:  Indicates dependencies. Seeing includes like `document.h`, `element_traversal.h`, `html_element.h`, `html_names.h`, `json_parser.h` strongly suggests interaction with the DOM and JSON.
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * `mojom::blink::WebPage`, `schema_org::mojom::blink::Entity`: These suggest data structures related to web pages and structured data (Schema.org).
    * `ExtractMetadata`, `ExtractEntity`, `ExtractTopLevelEntity`:  Function names clearly indicate an extraction process.
    * `kJSONLDKeyType`, `kJSONLDKeyGraph`: These constants point to the handling of JSON-LD.
    * `html_names::kScriptTag`, `"application/ld+json"`:  This immediately signals the extraction of structured data from `<script>` tags.

3. **High-Level Functionality Identification:** Based on the initial scan, the core functionality is likely:  **Extracting metadata from a web page, specifically structured data in JSON-LD format, and organizing it into a structured representation.**  The mention of Schema.org further refines this.

4. **Detailed Function Analysis (Top-Down or Bottom-Up):** I can now dive into the functions for a more granular understanding. I'll choose a slightly bottom-up approach here, starting with the helper functions.

    * **`IsSupportedType`:** This function checks if a given `AtomicString` (likely a string representing a Schema.org type) is in a predefined set. This immediately suggests that the extractor is selective about the types of entities it processes. *Connection to HTML: This type information usually comes from the `@type` property within JSON-LD embedded in the HTML.*
    * **`ParseRepeatedValue`:** This function handles JSON arrays (repeated values) within the structured data. It checks for type consistency and handles different JSON types (boolean, integer, string, object). It also has limits (`kMaxRepeatedSize`). *Connection to JSON: This is directly related to parsing JSON arrays.*
    * **`ExtractEntity`:** This is a core function. It recursively extracts properties and their values from a JSON object. It handles different JSON value types and calls `ParseRepeatedValue` for arrays. It respects the `kMaxDepth` limit, preventing infinite recursion. *Connection to JSON: This function parses JSON objects and extracts key-value pairs.*
    * **`ExtractTopLevelEntity`:** This function takes a JSON object and, if its `@type` is supported, calls `ExtractEntity` to process it. *Connection to JSON-LD: This handles the top-level entities defined in the JSON-LD.*
    * **`ExtractEntitiesFromArray`:** This function iterates through a JSON array and processes each object as a potential top-level entity. *Connection to JSON-LD: This handles the `@graph` structure in JSON-LD.*
    * **`ExtractEntityFromTopLevelObject`:** This function checks for the `@graph` key and processes entities within it, and also processes the top-level object itself. *Connection to JSON-LD:  This handles different ways JSON-LD can be structured.*
    * **`ExtractMetadata`:** This is the main extraction logic. It finds `<script type="application/ld+json">` elements, parses their content as JSON, and then calls the appropriate extraction functions based on whether the JSON is an array or an object. It also handles parsing errors. *Connection to HTML and JSON-LD: This directly interacts with HTML `<script>` tags and parses JSON-LD content.*
    * **`DocumentMetadataExtractor::Extract`:** This is the entry point. It checks if it's the main frame and then calls `ExtractMetadata`. It creates a `WebPage` object and populates it with the extracted data. *Connection to DOM and the overall extraction process.*

5. **Identifying Relationships to Web Technologies:**  As I analyzed the functions, I specifically looked for interactions with HTML, CSS, and JavaScript concepts.

    * **HTML:** The code directly interacts with HTML elements (`<script>`), attributes (`type`), and the DOM structure (traversal).
    * **JavaScript:** While this is C++ code, the *purpose* is to extract data often generated or embedded using JavaScript. The JSON-LD itself is often manipulated by JavaScript on the page.
    * **CSS:**  Less direct interaction. The presence of metadata *can* influence how a page is rendered (e.g., structured data for rich snippets), but the extractor itself doesn't directly parse CSS.

6. **Logic and Assumptions:**  I considered the conditions and assumptions within the code.

    * **Maximum Depth (`kMaxDepth`):**  This is a crucial constraint to prevent excessive processing and recursion.
    * **Maximum String Length (`kMaxStringLength`):**  Limits the size of extracted strings.
    * **Maximum Fields (`kMaxNumFields`) and Repeated Size (`kMaxRepeatedSize`):**  These are limitations imposed by App Indexing.
    * **Type Checking:** The code rigorously checks JSON types and handles inconsistencies.
    * **JSON-LD Structure:** The code understands the basic structure of JSON-LD, including `@type` and `@graph`.

7. **Potential Errors and User Mistakes:**  I thought about what could go wrong.

    * **Invalid JSON:**  Malformed JSON in the `<script>` tag is a common error.
    * **Incorrect `@type`:** Using unsupported Schema.org types.
    * **Exceeding Limits:**  Having deeply nested JSON-LD or very large arrays.
    * **Mixed Types in Arrays:**  Not adhering to the JSON-LD specification for consistent types within arrays.

8. **Debugging Scenario:**  I imagined a scenario where a developer might need to investigate why metadata isn't being extracted correctly. This involves tracing the user's actions leading to the code execution and the steps a developer might take.

9. **Structuring the Answer:** Finally, I organized my findings into the requested categories: functionality, relationships to web technologies, logic and assumptions, potential errors, and debugging. I used clear examples to illustrate the concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just extracts JSON."  **Correction:**  Realized it's specifically *JSON-LD* and tied to Schema.org, which is more specific and important.
* **Initial thought:** "CSS isn't relevant." **Refinement:**  Acknowledged the indirect influence of metadata on rendering.
* **During function analysis:** Paid attention to the limitations and constraints (e.g., `kMaxDepth`), as these are important for understanding the behavior of the extractor.

By following these steps, combining high-level understanding with detailed analysis, and focusing on the relationships to the broader web context, I could produce a comprehensive explanation of the provided C++ code.
这个文件 `document_metadata_extractor.cc` 的主要功能是从 HTML 文档中提取结构化元数据，特别是使用 JSON-LD 格式嵌入的元数据。这些提取的元数据被组织成特定的数据结构，用于 Chromium 浏览器的其他部分，例如 App Indexing。

以下是其功能的详细列表：

**核心功能:**

1. **识别并解析 JSON-LD:**
   - 它会遍历 DOM 树，查找 `type` 属性为 `application/ld+json` 的 `<script>` 标签。
   - 它使用 `ParseJSONWithCommentsDeprecated` 函数解析这些标签内的 JSON 内容。

2. **提取 Schema.org 实体:**
   - 它将解析后的 JSON 数据解释为 Schema.org 实体。Schema.org 是一种用于结构化数据的词汇表，用于描述网页上的事物。
   - 它将 JSON 对象映射到 `schema_org::mojom::blink::Entity` 对象，该对象包含实体的类型和属性。

3. **处理 JSON-LD 的不同结构:**
   - 它能够处理顶层是 JSON 对象或 JSON 数组的 JSON-LD 数据。
   - 它能识别并处理 JSON-LD 中的 `@graph` 关键字，该关键字用于定义一组相关的实体。

4. **限制提取深度和大小:**
   - 为了防止无限循环和处理过大的数据，它限制了 JSON 对象的嵌套深度 (`kMaxDepth`)。
   - 它还限制了字符串的长度 (`kMaxStringLength`)、字段的数量 (`kMaxNumFields`) 和重复字段的大小 (`kMaxRepeatedSize`)，这些限制通常与使用提取数据的下游服务（如 App Indexing）的限制相匹配。

5. **数据类型转换和处理:**
   - 它将 JSON 的基本数据类型（布尔值、整数、浮点数、字符串）转换为 `schema_org::mojom::blink::Values` 中的相应类型。
   - 对于浮点数，它将其转换为字符串表示，因为 App Indexing 不直接支持浮点数。

6. **过滤不支持的类型:**
   - `IsSupportedType` 函数定义了一组它关心的 Schema.org 类型。它只会提取这些类型的实体，忽略其他类型。

7. **构建 `WebPage` 对象:**
   - 最终，它将提取到的实体列表、文档的 URL 和标题组合成一个 `mojom::blink::WebPage` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **与 JavaScript 的关系:**
    - **生成 JSON-LD:** 开发者通常使用 JavaScript 在网页上动态生成和嵌入 JSON-LD 数据。`document_metadata_extractor.cc` 的目标是解析这些由 JavaScript 生成的数据。
    - **示例:** 一个电商网站可能使用 JavaScript 根据商品信息动态生成以下 JSON-LD 并插入到 `<script>` 标签中：
      ```html
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example Product",
        "description": "A great product.",
        "offers": {
          "@type": "Offer",
          "priceCurrency": "USD",
          "price": "19.99"
        }
      }
      </script>
      ```
      `document_metadata_extractor.cc` 会解析这段 JSON，提取 `Product` 实体及其 `name`、`description` 和 `offers` 属性。

* **与 HTML 的关系:**
    - **定位 JSON-LD 数据:**  它通过查找特定的 HTML 标签 (`<script type="application/ld+json">`) 来找到需要解析的元数据。
    - **DOM 遍历:**  它使用 Blink 的 DOM 遍历 API (`ElementTraversal::DescendantsOf`) 来搜索文档中的 `<script>` 标签。
    - **示例:** 上述的 HTML 代码片段直接展示了 JSON-LD 如何嵌入到 HTML 中。`document_metadata_extractor.cc` 的代码会找到这个 `<script>` 标签并提取其 `textContent`。

* **与 CSS 的关系:**
    - **间接关系:** `document_metadata_extractor.cc` 主要关注结构化数据，与 CSS 的关系较为间接。虽然 CSS 用于控制网页的呈现，但提取的元数据可能会被用于增强搜索结果的展示（例如，通过富媒体摘要），这在某种程度上受到 CSS 的影响。
    - **示例:**  虽然 `document_metadata_extractor.cc` 不解析 CSS，但它提取的关于一个 `Product` 的信息（名称、价格、图片等）可能会被搜索引擎用于生成带有图片和价格的搜索结果，而这些搜索结果的样式是由搜索引擎的 CSS 控制的。

**逻辑推理的假设输入与输出:**

**假设输入:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>My Business</title>
</head>
<body>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "LocalBusiness",
    "name": "My Awesome Cafe",
    "address": {
      "@type": "PostalAddress",
      "streetAddress": "123 Main St",
      "addressLocality": "Anytown",
      "addressRegion": "CA"
    },
    "telephone": "+1-555-1212"
  }
  </script>
</body>
</html>
```

**预期输出 (简化的 `WebPage` 对象表示):**

```
WebPage {
  url: "当前页面的 URL",
  title: "My Business",
  entities: [
    Entity {
      type: "LocalBusiness",
      properties: [
        Property { name: "name", values: StringValues(["My Awesome Cafe"]) },
        Property { name: "address", values: EntityValues([
          Entity {
            type: "PostalAddress",
            properties: [
              Property { name: "streetAddress", values: StringValues(["123 Main St"]) },
              Property { name: "addressLocality", values: StringValues(["Anytown"]) },
              Property { name: "addressRegion", values: StringValues(["CA"]) }
            ]
          }
        ]) },
        Property { name: "telephone", values: StringValues(["+1-555-1212"]) }
      ]
    }
  ]
}
```

**涉及用户或者编程常见的使用错误举例说明:**

1. **JSON-LD 格式错误:**
   - **错误:**  在 `<script type="application/ld+json">` 标签内的 JSON 数据格式不正确，例如缺少引号、逗号或括号不匹配。
   - **后果:** `document_metadata_extractor.cc` 会调用 `ParseJSONWithCommentsDeprecated` 失败，导致无法提取任何元数据。
   - **用户操作:** 开发者手动编写或使用错误的工具生成 JSON-LD。

2. **使用不支持的 Schema.org 类型:**
   - **错误:** 在 JSON-LD 中使用了 `IsSupportedType` 函数中未包含的 Schema.org 类型。
   - **后果:**  `document_metadata_extractor.cc` 会忽略这些类型的实体。
   - **用户操作:** 开发者使用了不在预定义支持列表中的 Schema.org 词汇。

3. **JSON-LD 嵌套过深:**
   - **错误:** JSON-LD 数据中的对象嵌套层级超过了 `kMaxDepth` (当前设置为 4)。
   - **后果:** 超过最大深度的嵌套对象及其属性将被忽略。
   - **用户操作:** 开发者创建了过于复杂的、嵌套层次很深的 JSON-LD 结构。

4. **字符串值过长:**
   - **错误:** JSON-LD 中的某个字符串属性的值长度超过了 `kMaxStringLength` (当前设置为 200)。
   - **后果:** 字符串值会被截断。
   - **用户操作:** 开发者在 JSON-LD 中包含了非常长的文本描述或其他字符串值。

5. **在一个数组中混合不同的数据类型:**
   - **错误:**  JSON-LD 数组中包含了不同类型的元素 (例如，一个数组中既有字符串又有数字)。
   - **后果:** `ParseRepeatedValue` 函数会检测到类型不一致并返回 `false`，导致整个属性被丢弃。
   - **用户操作:** 开发者在数组中错误地混合了数据类型，违反了通常的结构化数据约定。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者发现他们的网页的结构化数据没有被正确地提取出来，他们可能会采取以下调试步骤，最终可能会深入到 `document_metadata_extractor.cc` 的执行：

1. **用户访问网页:** 用户在 Chrome 浏览器中访问包含结构化数据的网页。

2. **Blink 渲染引擎开始解析 HTML:** Chrome 的 Blink 渲染引擎开始解析下载的 HTML 文档。

3. **解析器遇到 `<script type="application/ld+json">` 标签:**  HTML 解析器会识别出包含 JSON-LD 数据的 `<script>` 标签。

4. **触发元数据提取流程:**  Blink 的其他组件会触发文档元数据提取的流程，其中就包括 `DocumentMetadataExtractor::Extract` 函数的调用。

5. **`DocumentMetadataExtractor::Extract` 被调用:** 这个函数接收 `Document` 对象作为参数。

6. **遍历 DOM 树:**  `ExtractMetadata` 函数会被调用，它会遍历文档的 DOM 树，查找 `<script type="application/ld+json">` 标签。

7. **解析 JSON-LD 内容:** 找到匹配的标签后，`ParseJSONWithCommentsDeprecated` 函数被用来解析标签的 `textContent`。

8. **提取实体和属性:** 根据解析后的 JSON 数据结构，`ExtractEntity`, `ExtractTopLevelEntity`, `ExtractEntitiesFromArray` 等函数会被调用，将 JSON 数据映射到 `Entity` 和 `Property` 对象。

9. **构建 `WebPage` 对象:**  提取到的实体和其他信息被组装成 `WebPage` 对象。

10. **将元数据传递给其他 Chrome 组件:**  构建好的 `WebPage` 对象会被传递给其他需要这些元数据的 Chrome 组件，例如 App Indexing。

**调试线索:**

如果开发者怀疑 `document_metadata_extractor.cc` 存在问题，他们可能会：

* **在 Chromium 源代码中设置断点:** 在 `DocumentMetadataExtractor::Extract` 或其调用的其他函数中设置断点，以观察代码的执行流程和变量的值。
* **查看日志输出:** 检查是否有 `LOG(ERROR)` 相关的输出，这可能指示 JSON 解析失败或其他错误。
* **检查 `WebPage` 对象的内容:**  查看最终生成的 `WebPage` 对象，确认其中包含的实体和属性是否符合预期。
* **使用 Chrome 的开发者工具:** 虽然开发者工具不直接显示 C++ 代码的执行，但 Network 面板可以用来检查网页的 HTML 源代码，确认 JSON-LD 是否正确嵌入。
* **使用在线 JSON-LD 验证工具:** 验证网页上的 JSON-LD 是否符合规范，排除 JSON 格式错误的可能性。

通过以上分析，我们可以了解到 `document_metadata_extractor.cc` 在 Chromium 浏览器中扮演着重要的角色，它负责从网页中提取结构化的元数据，并将这些数据提供给其他组件使用，从而增强浏览器的功能和用户体验。理解其工作原理有助于开发者正确地嵌入结构化数据，并进行有效的调试。

Prompt: 
```
这是目录为blink/renderer/modules/document_metadata/document_metadata_extractor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/document_metadata/document_metadata_extractor.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "components/schema_org/common/metadata.mojom-blink.h"
#include "third_party/blink/public/mojom/document_metadata/document_metadata.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

using mojom::blink::WebPage;
using mojom::blink::WebPagePtr;
using schema_org::mojom::blink::Entity;
using schema_org::mojom::blink::EntityPtr;
using schema_org::mojom::blink::Property;
using schema_org::mojom::blink::PropertyPtr;
using schema_org::mojom::blink::Values;
using schema_org::mojom::blink::ValuesPtr;

// App Indexing enforces a max nesting depth of 5. Our top level message
// corresponds to the WebPage, so this only leaves 4 more levels. We will parse
// entites up to this depth, and ignore any further nesting. If an object at the
// max nesting depth has a property corresponding to an entity, that property
// will be dropped. Note that we will still parse json-ld blocks deeper than
// this, but it won't be passed to App Indexing.
constexpr int kMaxDepth = 4;
// Some strings are very long, and we don't currently use those, so limit string
// length to something reasonable to avoid undue pressure on Icing. Note that
// App Indexing supports strings up to length 20k.
constexpr wtf_size_t kMaxStringLength = 200;
// Enforced by App Indexing, so stop processing early if possible.
constexpr wtf_size_t kMaxNumFields = 20;
// Enforced by App Indexing, so stop processing early if possible.
constexpr wtf_size_t kMaxRepeatedSize = 100;

constexpr char kJSONLDKeyType[] = "@type";
constexpr char kJSONLDKeyGraph[] = "@graph";
bool IsSupportedType(AtomicString type) {
  DEFINE_STATIC_LOCAL(
      HashSet<AtomicString>, elements,
      ({// Common types that include addresses.
        AtomicString("AutoDealer"), AtomicString("Hotel"),
        AtomicString("LocalBusiness"), AtomicString("Organization"),
        AtomicString("Person"), AtomicString("Place"),
        AtomicString("PostalAddress"), AtomicString("Product"),
        AtomicString("Residence"), AtomicString("Restaurant"),
        AtomicString("SingleFamilyResidence"),
        // Common types including phone numbers
        AtomicString("Store"), AtomicString("ContactPoint"),
        AtomicString("LodgingBusiness")}));
  return type && elements.Contains(type);
}

void ExtractEntity(const JSONObject&, int recursion_level, Entity&);

bool ParseRepeatedValue(const JSONArray& arr,
                        int recursion_level,
                        ValuesPtr& values) {
  if (arr.size() < 1) {
    return false;
  }

  const JSONValue::ValueType type = arr.at(0)->GetType();
  switch (type) {
    case JSONValue::ValueType::kTypeNull:
      return false;
    case JSONValue::ValueType::kTypeBoolean:
      values = Values::NewBoolValues({});
      break;
    case JSONValue::ValueType::kTypeInteger:
      values = Values::NewLongValues({});
      break;
    // App Indexing doesn't support double type, so just encode its decimal
    // value as a string instead.
    case JSONValue::ValueType::kTypeDouble:
    case JSONValue::ValueType::kTypeString:
      values = Values::NewStringValues({});
      break;
    case JSONValue::ValueType::kTypeObject:
      if (recursion_level + 1 >= kMaxDepth) {
        return false;
      }
      values = Values::NewEntityValues({});
      break;
    case JSONArray::ValueType::kTypeArray:
      // App Indexing doesn't support nested arrays.
      return false;
  }

  const wtf_size_t arr_size = std::min(arr.size(), kMaxRepeatedSize);
  for (wtf_size_t i = 0; i < arr_size; ++i) {
    const JSONValue* const element = arr.at(i);
    if (element->GetType() != type) {
      // App Indexing doesn't support mixed types. If there are mixed
      // types in the parsed object, we will drop the property.
      return false;
    }
    switch (type) {
      case JSONValue::ValueType::kTypeBoolean: {
        bool v;
        element->AsBoolean(&v);
        values->get_bool_values().push_back(v);
        continue;
      }
      case JSONValue::ValueType::kTypeInteger: {
        int v;
        element->AsInteger(&v);
        values->get_long_values().push_back(v);
        continue;
      }
      case JSONValue::ValueType::kTypeDouble: {
        // App Indexing doesn't support double type, so just encode its decimal
        // value as a string instead.
        double v;
        element->AsDouble(&v);
        String s = String::Number(v);
        s.Truncate(kMaxStringLength);
        values->get_string_values().push_back(s);
        continue;
      }
      case JSONValue::ValueType::kTypeString: {
        String v;
        element->AsString(&v);
        v.Truncate(kMaxStringLength);
        values->get_string_values().push_back(v);
        continue;
      }
      case JSONValue::ValueType::kTypeObject: {
        auto entity = Entity::New();
        ExtractEntity(*(JSONObject::Cast(element)), recursion_level + 1,
                      *entity);
        values->get_entity_values().push_back(std::move(entity));
        continue;
      }
      case JSONValue::ValueType::kTypeNull:
      case JSONValue::ValueType::kTypeArray:
        CHECK(false);
    }
  }
  return true;
}

void ExtractEntity(const JSONObject& val, int recursion_level, Entity& entity) {
  if (recursion_level >= kMaxDepth) {
    return;
  }

  String type;
  val.GetString(kJSONLDKeyType, &type);
  if (!type) {
    type = "Thing";
  }
  entity.type = type;
  for (wtf_size_t i = 0; i < std::min(val.size(), kMaxNumFields); ++i) {
    PropertyPtr property = Property::New();
    const JSONObject::Entry& entry = val.at(i);
    property->name = entry.first;
    if (property->name == kJSONLDKeyType) {
      continue;
    }

    bool add_property = true;

    switch (entry.second->GetType()) {
      case JSONValue::ValueType::kTypeBoolean: {
        bool v;
        val.GetBoolean(entry.first, &v);
        property->values = Values::NewBoolValues({v});
      } break;
      case JSONValue::ValueType::kTypeInteger: {
        int v;
        val.GetInteger(entry.first, &v);
        property->values = Values::NewLongValues({v});
      } break;
      case JSONValue::ValueType::kTypeDouble: {
        double v;
        val.GetDouble(entry.first, &v);
        String s = String::Number(v);
        s.Truncate(kMaxStringLength);
        property->values = Values::NewStringValues({s});
      } break;
      case JSONValue::ValueType::kTypeString: {
        String v;
        val.GetString(entry.first, &v);
        v.Truncate(kMaxStringLength);
        property->values = Values::NewStringValues({v});
      } break;
      case JSONValue::ValueType::kTypeObject: {
        if (recursion_level + 1 >= kMaxDepth) {
          add_property = false;
          break;
        }
        Vector<EntityPtr> entities;
        entities.push_back(Entity::New());
        ExtractEntity(*(val.GetJSONObject(entry.first)), recursion_level + 1,
                      *entities[0]);
        property->values = Values::NewEntityValues(std::move(entities));
      } break;
      case JSONValue::ValueType::kTypeArray:
        add_property = ParseRepeatedValue(*(val.GetArray(entry.first)),
                                          recursion_level, property->values);
        break;
      case JSONValue::ValueType::kTypeNull:
        add_property = false;
        break;
    }
    if (add_property)
      entity.properties.push_back(std::move(property));
  }
}

void ExtractTopLevelEntity(const JSONObject& val, Vector<EntityPtr>& entities) {
  // Now we have a JSONObject which corresponds to a single (possibly nested)
  // entity.
  EntityPtr entity = Entity::New();
  String type;
  val.GetString(kJSONLDKeyType, &type);
  if (!IsSupportedType(AtomicString(type))) {
    return;
  }
  ExtractEntity(val, 0, *entity);
  entities.push_back(std::move(entity));
}

void ExtractEntitiesFromArray(const JSONArray& arr,
                              Vector<EntityPtr>& entities) {
  for (wtf_size_t i = 0; i < arr.size(); ++i) {
    const JSONValue* val = arr.at(i);
    if (val->GetType() == JSONValue::ValueType::kTypeObject) {
      ExtractTopLevelEntity(*(JSONObject::Cast(val)), entities);
    }
  }
}

void ExtractEntityFromTopLevelObject(const JSONObject& val,
                                     Vector<EntityPtr>& entities) {
  const JSONArray* graph = val.GetArray(kJSONLDKeyGraph);
  if (graph) {
    ExtractEntitiesFromArray(*graph, entities);
  }
  ExtractTopLevelEntity(val, entities);
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum ExtractionStatus {
  kOK,
  kEmpty,
  kParseFailure,
  kWrongType,
  kMaxValue = kWrongType,
};

ExtractionStatus ExtractMetadata(const Element& root,
                                 Vector<EntityPtr>& entities) {
  for (Element& element : ElementTraversal::DescendantsOf(root)) {
    if (element.HasTagName(html_names::kScriptTag) &&
        element.FastGetAttribute(html_names::kTypeAttr) ==
            "application/ld+json") {
      // TODO(crbug.com/1264024): Deprecate JSON comments here, if possible.
      std::unique_ptr<JSONValue> json =
          ParseJSONWithCommentsDeprecated(element.textContent());
      if (!json) {
        LOG(ERROR) << "Failed to parse json.";
        return ExtractionStatus::kParseFailure;
      }
      switch (json->GetType()) {
        case JSONValue::ValueType::kTypeArray:
          ExtractEntitiesFromArray(*(JSONArray::Cast(json.get())), entities);
          break;
        case JSONValue::ValueType::kTypeObject:
          ExtractEntityFromTopLevelObject(*(JSONObject::Cast(json.get())),
                                          entities);
          break;
        default:
          return ExtractionStatus::kWrongType;
      }
    }
  }
  if (entities.empty()) {
    return ExtractionStatus::kEmpty;
  }
  return ExtractionStatus::kOK;
}

}  // namespace

WebPagePtr DocumentMetadataExtractor::Extract(const Document& document) {
  TRACE_EVENT0("blink", "DocumentMetadataExtractor::Extract");

  if (!document.GetFrame() || !document.GetFrame()->IsMainFrame())
    return nullptr;

  Element* html = document.documentElement();
  if (!html)
    return nullptr;

  WebPagePtr page = WebPage::New();

  // Traverse the DOM tree and extract the metadata.
  ExtractionStatus status = ExtractMetadata(*html, page->entities);
  if (status != ExtractionStatus::kOK) {
    return nullptr;
  }

  page->url = document.Url();
  page->title = document.title();
  return page;
}

}  // namespace blink

"""

```