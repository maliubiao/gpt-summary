Response:
The user wants to understand the functionality of the `document_metadata_extractor_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, its relation to web technologies, provide examples of its behavior, discuss potential user errors, and outline how a user's actions might lead to this code being executed.

Here's a breakdown of the analysis:

1. **Purpose of the file:** This file contains unit tests for the `DocumentMetadataExtractor` class. The tests verify that the extractor correctly identifies and parses structured data (specifically JSON-LD) embedded within HTML documents.

2. **Relation to Javascript, HTML, CSS:**
    - **HTML:** The tests directly manipulate HTML content by inserting `<script>` tags with `application/ld+json` type. This demonstrates the extractor's reliance on HTML structure.
    - **Javascript:**  While the tests don't directly execute Javascript, the extracted data (JSON-LD) is often used by Javascript on the page for various purposes like SEO enhancements or richer user experiences. The extractor makes this data accessible to the browser.
    - **CSS:**  CSS is not directly involved in the *extraction* process. However, the *purpose* of the extracted metadata might influence how content is styled or presented, although this is outside the scope of this specific test file.

3. **Logic and Examples:** The tests cover various scenarios of parsing JSON-LD, including:
    - Basic extraction with string values.
    - Extraction from `<head>` and `<body>`.
    - Handling different data types (boolean, long, double).
    - Handling multiple JSON-LD blocks.
    - Parsing nested objects.
    - Parsing arrays of values.
    - Parsing arrays of objects.
    - Handling string truncation.
    - Validating the presence of `@type`.
    - Ignoring unsupported types.
    - Handling limits on array sizes and field counts.
    - Ignoring empty arrays and null values.
    - Ignoring mixed-type arrays and nested arrays.
    - Enforcing maximum nesting depth.

    I can provide specific examples of input HTML and the expected output `WebPage` object structure.

4. **User/Programming Errors:**
    - **Incorrect `type` attribute:** Using a `type` other than `application/ld+json` will cause the extractor to ignore the script block.
    - **Malformed JSON:**  Syntax errors in the JSON-LD will likely prevent successful parsing.
    - **Missing `@type`:** The extractor enforces the presence of the `@type` property for entities.

5. **User Operation and Debugging:** A user browsing a webpage containing embedded JSON-LD will trigger this code. As a debugging clue, understanding how the extraction process works is crucial for identifying issues with how metadata is being interpreted by the browser.

Plan:
- Start with a high-level description of the file's purpose.
- Elaborate on the relationship with HTML, Javascript, and CSS, providing concrete examples.
- For logic and examples, choose a few representative test cases and illustrate the input and expected output.
- Explain common user/programming errors related to JSON-LD.
- Describe the user interaction leading to this code and how it can be used for debugging.
这个文件 `document_metadata_extractor_test.cc` 是 Chromium Blink 引擎中一个单元测试文件，它的主要功能是**测试 `DocumentMetadataExtractor` 类**的功能。 `DocumentMetadataExtractor` 类的作用是从 HTML 文档中提取结构化的元数据，特别是使用 `<script type="application/ld+json">` 嵌入的 JSON-LD 数据。

**具体来说，这个测试文件会模拟各种 HTML 结构和 JSON-LD 数据，然后断言 `DocumentMetadataExtractor::Extract()` 方法的输出是否符合预期。**

**与 Javascript, HTML, CSS 的关系：**

这个文件与 HTML 和 Javascript 有直接关系，与 CSS 没有直接关系。

* **HTML:**
    * **功能关系：** `DocumentMetadataExtractor` 的核心功能就是解析 HTML 文档中特定标签（`<script type="application/ld+json">`）的内容。
    * **举例说明：** 测试用例中会设置不同的 HTML 内容，例如：
        ```c++
        SetHTMLInnerHTML(
            "<body>"
            "<script type=\"application/ld+json\">"
            "{\"@type\": \"Restaurant\", \"name\": \"Special characters for ya >_<;\"}"
            "</script>"
            "</body>");
        ```
        这段 HTML 代码包含了 JSON-LD 数据，测试会验证 `DocumentMetadataExtractor` 是否能正确解析出 `Restaurant` 类型的实体，并提取其 `name` 属性。

* **Javascript:**
    * **功能关系：**  虽然这个测试文件本身是用 C++ 编写的，但它测试的对象是处理网页中 Javascript 嵌入的 JSON-LD 数据的能力。 JSON-LD 是一种用于在 Web 上发布结构化数据的 Javascript Notation。
    * **举例说明：** 上面的 HTML 例子中，JSON-LD 数据本身就是一种 Javascript 对象表示法。`DocumentMetadataExtractor` 的作用是将这种 Javascript 数据结构转化为 Blink 引擎内部更容易处理的 `WebPage` 和 `Entity` 等数据结构。

* **CSS:**
    * **功能关系：** CSS 主要负责网页的样式和布局，与 `DocumentMetadataExtractor` 的数据提取功能没有直接关系。

**逻辑推理 (假设输入与输出):**

以下列举几个测试用例，展示假设的输入 HTML 和 `DocumentMetadataExtractor::Extract()` 方法的预期输出：

**假设输入 1:**

```html
<html>
<head>
  <title>My neat website</title>
</head>
<body>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "My neat website",
    "url": "http://www.example.com/"
  }
  </script>
</body>
</html>
```

**预期输出 1 (简化表示):**

```
WebPage {
  url: "http://www.example.com/",
  title: "My neat website",
  entities: [
    Entity {
      type: "WebPage",
      properties: [
        Property { name: "name", values: ["My neat website"] },
        Property { name: "url", values: ["http://www.example.com/"] }
      ]
    }
  ]
}
```

**假设输入 2 (嵌套对象):**

```html
<html>
<body>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Restaurant",
    "name": "Delicious Bistro",
    "address": {
      "@type": "PostalAddress",
      "streetAddress": "123 Main St",
      "addressLocality": "Anytown"
    }
  }
  </script>
</body>
</html>
```

**预期输出 2 (简化表示):**

```
WebPage {
  entities: [
    Entity {
      type: "Restaurant",
      properties: [
        Property { name: "name", values: ["Delicious Bistro"] },
        Property {
          name: "address",
          values: [
            Entity {
              type: "PostalAddress",
              properties: [
                Property { name: "streetAddress", values: ["123 Main St"] },
                Property { name: "addressLocality", values: ["Anytown"] }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

**涉及用户或者编程常见的使用错误 (举例说明):**

* **错误的 `<script>` 标签 `type` 属性:**
    * **错误示例：**
      ```html
      <script type="text/json">
      {"@type": "Restaurant", "name": "My Restaurant"}
      </script>
      ```
    * **说明：** 如果用户将 `<script>` 标签的 `type` 属性设置为其他值（例如 `text/json`），`DocumentMetadataExtractor` 将不会识别并解析其中的 JSON-LD 数据。这是因为该提取器专门寻找 `application/ld+json` 类型的 script 标签。

* **JSON-LD 格式错误:**
    * **错误示例：**
      ```html
      <script type="application/ld+json">
      {"@type": "Restaurant", "name": "My Restaurant" } // 缺少结尾的引号
      </script>
      ```
    * **说明：**  如果 JSON-LD 数据格式不正确（例如缺少引号、逗号等），JSON 解析器会报错，`DocumentMetadataExtractor` 将无法提取有效数据。

* **缺少 `@type` 属性:**
    * **错误示例：**
      ```html
      <script type="application/ld+json">
      {"name": "My Restaurant"}
      </script>
      ```
    * **说明：**  `DocumentMetadataExtractor` 的测试用例中包含 `TEST_F(DocumentMetadataExtractorTest, enforceTypeExists)`，表明该提取器强制要求 JSON-LD 对象必须包含 `@type` 属性，用于标识实体的类型。缺少此属性可能导致提取失败或被忽略。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页。**
2. **该网页的 HTML 源代码中包含了 `<script type="application/ld+json">` 标签，其中嵌入了 JSON-LD 格式的结构化数据。** 网站开发者可能为了 SEO 优化、社交媒体分享优化或其他目的添加了这些元数据。
3. **Blink 引擎开始解析该网页的 HTML 内容。**
4. **当解析器遇到 `<script type="application/ld+json">` 标签时，会触发相关的处理逻辑。**
5. **`DocumentMetadataExtractor::Extract()` 方法会被调用，传入表示当前文档的对象。**
6. **该方法会查找并解析文档中的所有 `application/ld+json` script 标签的内容。**
7. **解析后的 JSON-LD 数据会被转换成 Blink 引擎内部的 `WebPage` 和 `Entity` 等数据结构。**
8. **这些提取出的元数据可以被浏览器用于各种目的，例如：**
    * **搜索引擎优化 (SEO):**  搜索引擎可以利用这些结构化数据更好地理解网页内容。
    * **富媒体搜索结果:**  在搜索结果中展示更丰富的信息，例如餐厅的评分、地址等。
    * **社交媒体分享:**  社交平台可以利用这些数据生成更吸引人的分享卡片。

**作为调试线索：**

* 如果开发者怀疑网页上的结构化数据没有被正确提取，他们可以检查 `document_metadata_extractor_test.cc` 中的测试用例，看看是否有类似的场景被覆盖。
* 如果发现提取行为不符合预期，开发者可以编写新的测试用例来复现问题，从而帮助定位 `DocumentMetadataExtractor` 类中的 bug。
* 通过查看测试用例，开发者可以了解 `DocumentMetadataExtractor` 支持哪些 JSON-LD 特性，以及对数据格式的限制。
* 当浏览器在处理包含 JSON-LD 的网页时出现问题，开发人员可能会查看 `DocumentMetadataExtractor` 的代码和相关的测试，以了解数据提取阶段是否正常工作。 例如，如果某些元数据没有出现在预期的 API 中，可能需要在提取器中进行调试。

总而言之，`document_metadata_extractor_test.cc` 是保证 Chromium Blink 引擎能够正确解析和提取网页中结构化元数据（特别是 JSON-LD）的关键组成部分，它通过大量的测试用例覆盖了各种可能的场景和边界情况，确保了该功能的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/modules/document_metadata/document_metadata_extractor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/document_metadata/document_metadata_extractor.h"

#include <memory>
#include <utility>

#include "components/schema_org/common/metadata.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/document_metadata/document_metadata.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

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

class DocumentMetadataExtractorTest : public PageTestBase {
 public:
  DocumentMetadataExtractorTest() = default;

 protected:
  void TearDown() override {
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  WebPagePtr Extract() {
    return DocumentMetadataExtractor::Extract(GetDocument());
  }

  void SetHTMLInnerHTML(const String&);

  void SetURL(const String&);

  void SetTitle(const String&);

  PropertyPtr CreateStringProperty(const String& name, const String& value);

  PropertyPtr CreateBooleanProperty(const String& name, const bool& value);

  PropertyPtr CreateLongProperty(const String& name, const int64_t& value);

  PropertyPtr CreateEntityProperty(const String& name, EntityPtr value);

  WebPagePtr CreateWebPage(const String& url, const String& title);
};

void DocumentMetadataExtractorTest::SetHTMLInnerHTML(
    const String& html_content) {
  GetDocument().documentElement()->setInnerHTML((html_content));
}

void DocumentMetadataExtractorTest::SetURL(const String& url) {
  GetDocument().SetURL(blink::KURL(url));
}

void DocumentMetadataExtractorTest::SetTitle(const String& title) {
  GetDocument().setTitle(title);
}

PropertyPtr DocumentMetadataExtractorTest::CreateStringProperty(
    const String& name,
    const String& value) {
  PropertyPtr property = Property::New();
  property->name = name;
  property->values = Values::NewStringValues({value});
  return property;
}

PropertyPtr DocumentMetadataExtractorTest::CreateBooleanProperty(
    const String& name,
    const bool& value) {
  PropertyPtr property = Property::New();
  property->name = name;
  property->values = Values::NewBoolValues({value});
  return property;
}

PropertyPtr DocumentMetadataExtractorTest::CreateLongProperty(
    const String& name,
    const int64_t& value) {
  PropertyPtr property = Property::New();
  property->name = name;
  property->values = Values::NewLongValues({value});
  return property;
}

PropertyPtr DocumentMetadataExtractorTest::CreateEntityProperty(
    const String& name,
    EntityPtr value) {
  PropertyPtr property = Property::New();
  property->name = name;
  Vector<EntityPtr> entities;
  entities.push_back(std::move(value));
  property->values = Values::NewEntityValues(std::move(entities));
  return property;
}

WebPagePtr DocumentMetadataExtractorTest::CreateWebPage(const String& url,
                                                        const String& title) {
  WebPagePtr page = WebPage::New();
  page->url = blink::KURL(url);
  page->title = title;
  return page;
}

TEST_F(DocumentMetadataExtractorTest, empty) {
  ASSERT_TRUE(Extract().is_null());
}

TEST_F(DocumentMetadataExtractorTest, basic) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Special characters for ya >_<;"));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, header) {
  SetHTMLInnerHTML(
      "<head>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</head>");

  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Special characters for ya >_<;"));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, booleanValue) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"open\": true"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(CreateBooleanProperty("open", true));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, longValue) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"long\": 1"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(CreateLongProperty("long", 1ll));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, doubleValue) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"double\": 1.5"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(CreateStringProperty("double", "1.5"));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, multiple) {
  SetHTMLInnerHTML(
      "<head>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</head>"
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</body>");

  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  for (int i = 0; i < 3; ++i) {
    EntityPtr restaurant = Entity::New();
    restaurant->type = "Restaurant";
    restaurant->properties.push_back(
        CreateStringProperty("name", "Special characters for ya >_<;"));

    expected->entities.push_back(std::move(restaurant));
  }
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, nested) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Ye ol greasy diner\","
      "\"address\": {"
      "\n"
      "  \"streetAddress\": \"123 Big Oak Road\","
      "  \"addressLocality\": \"San Francisco\""
      "  }\n"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Ye ol greasy diner"));

  EntityPtr address = Entity::New();
  address->type = "Thing";
  address->properties.push_back(
      CreateStringProperty("streetAddress", "123 Big Oak Road"));
  address->properties.push_back(
      CreateStringProperty("addressLocality", "San Francisco"));

  restaurant->properties.push_back(
      CreateEntityProperty("address", std::move(address)));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, repeated) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": [ \"First name\", \"Second name\" ]"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  PropertyPtr name = Property::New();
  name->name = "name";
  Vector<String> name_values;
  name_values.push_back("First name");
  name_values.push_back("Second name");
  name->values = Values::NewStringValues(name_values);

  restaurant->properties.push_back(std::move(name));

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, repeatedObject) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Ye ol greasy diner\","
      "\"address\": ["
      "\n"
      "  {"
      "  \"streetAddress\": \"123 Big Oak Road\","
      "  \"addressLocality\": \"San Francisco\""
      "  },\n"
      "  {"
      "  \"streetAddress\": \"123 Big Oak Road\","
      "  \"addressLocality\": \"San Francisco\""
      "  }\n"
      "]\n"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Ye ol greasy diner"));

  PropertyPtr address_property = Property::New();
  address_property->name = "address";
  Vector<EntityPtr> entities;
  for (int i = 0; i < 2; ++i) {
    EntityPtr address = Entity::New();
    address->type = "Thing";
    address->properties.push_back(
        CreateStringProperty("streetAddress", "123 Big Oak Road"));
    address->properties.push_back(
        CreateStringProperty("addressLocality", "San Francisco"));
    entities.push_back(std::move(address));
  }
  address_property->values = Values::NewEntityValues(std::move(entities));
  restaurant->properties.push_back(std::move(address_property));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, truncateLongString) {
  StringBuilder maxLengthString;
  for (int i = 0; i < 200; ++i) {
    maxLengthString.Append("a");
  }
  StringBuilder tooLongString;
  tooLongString.Append(maxLengthString);
  tooLongString.Append("a");
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"" +
      tooLongString.ToString() +
      "\""
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", maxLengthString.ToString()));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, enforceTypeExists) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_TRUE(extracted.is_null());
}

TEST_F(DocumentMetadataExtractorTest, UnhandledTypeIgnored) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"UnsupportedType\","
      "\"name\": \"Special characters for ya >_<;\""
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_TRUE(extracted.is_null());
}

TEST_F(DocumentMetadataExtractorTest, truncateTooManyValuesInField) {
  StringBuilder largeRepeatedField;
  largeRepeatedField.Append("[");
  for (int i = 0; i < 101; ++i) {
    largeRepeatedField.Append("\"a\"");
    if (i != 100) {
      largeRepeatedField.Append(", ");
    }
  }
  largeRepeatedField.Append("]");
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": " +
      largeRepeatedField.ToString() +
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  PropertyPtr name = Property::New();
  name->name = "name";
  Vector<String> name_values;
  for (int i = 0; i < 100; ++i) {
    name_values.push_back("a");
  }
  name->values = Values::NewStringValues(name_values);

  restaurant->properties.push_back(std::move(name));

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, truncateTooManyFields) {
  StringBuilder tooManyFields;
  for (int i = 0; i < 20; ++i) {
    tooManyFields.AppendFormat("\"%d\": \"a\"", i);
    if (i != 19) {
      tooManyFields.Append(",\n");
    }
  }
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\"," +
      tooManyFields.ToString() +
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  for (int i = 0; i < 19; ++i) {
    restaurant->properties.push_back(
        CreateStringProperty(String::Number(i), "a"));
  }

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, ignorePropertyWithEmptyArray) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": []"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, ignoreNullProperty) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": null"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, ignorePropertyWithMixedTypes) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": [ \"Name\", 1 ]"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, ignorePropertyWithNestedArray) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": [ [ \"Name\" ] ]"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";

  expected->entities.push_back(std::move(restaurant));

  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, enforceMaxNestingDepth) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Ye ol greasy diner\","
      "\"1\": {"
      "  \"2\": {"
      "    \"3\": {"
      "      \"4\": {"
      "        \"5\": 6"
      "      }\n"
      "    }\n"
      "  }\n"
      "}\n"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Ye ol greasy diner"));

  EntityPtr entity1 = Entity::New();
  entity1->type = "Thing";

  EntityPtr entity2 = Entity::New();
  entity2->type = "Thing";

  EntityPtr entity3 = Entity::New();
  entity3->type = "Thing";

  entity2->properties.push_back(CreateEntityProperty("3", std::move(entity3)));

  entity1->properties.push_back(CreateEntityProperty("2", std::move(entity2)));

  restaurant->properties.push_back(
      CreateEntityProperty("1", std::move(entity1)));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

TEST_F(DocumentMetadataExtractorTest, maxNestingDepthWithTerminalProperty) {
  SetHTMLInnerHTML(
      "<body>"
      "<script type=\"application/ld+json\">"
      "\n"
      "\n"
      "{\"@type\": \"Restaurant\","
      "\"name\": \"Ye ol greasy diner\","
      "\"1\": {"
      "  \"2\": {"
      "    \"3\": {"
      "      \"4\": 5"
      "    }\n"
      "  }\n"
      "}\n"
      "}\n"
      "\n"
      "</script>"
      "</body>");
  SetURL("http://www.test.com/");
  SetTitle("My neat website about cool stuff");

  WebPagePtr extracted = Extract();
  ASSERT_FALSE(extracted.is_null());

  WebPagePtr expected =
      CreateWebPage("http://www.test.com/", "My neat website about cool stuff");

  EntityPtr restaurant = Entity::New();
  restaurant->type = "Restaurant";
  restaurant->properties.push_back(
      CreateStringProperty("name", "Ye ol greasy diner"));

  EntityPtr entity1 = Entity::New();
  entity1->type = "Thing";

  EntityPtr entity2 = Entity::New();
  entity2->type = "Thing";

  EntityPtr entity3 = Entity::New();
  entity3->type = "Thing";

  entity3->properties.push_back(CreateLongProperty("4", 5));

  entity2->properties.push_back(CreateEntityProperty("3", std::move(entity3)));

  entity1->properties.push_back(CreateEntityProperty("2", std::move(entity2)));

  restaurant->properties.push_back(
      CreateEntityProperty("1", std::move(entity1)));

  expected->entities.push_back(std::move(restaurant));
  EXPECT_EQ(expected, extracted);
}

}  // namespace
}  // namespace blink

"""

```