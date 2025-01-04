Response:
The user wants me to analyze a C++ unit test file for the Chromium Blink engine. Specifically, the file `manifest_parser_unittest.cc` is responsible for testing the parsing of web app manifest files.

Here's a breakdown of how to approach the request:

1. **Identify the core functionality:** The file contains unit tests for the manifest parser. This means it tests how the parser handles different valid and invalid manifest configurations.

2. **Relate to web technologies (JavaScript, HTML, CSS):** The manifest file describes a web application, which is built using HTML, CSS, and JavaScript. The manifest provides metadata about the app, influencing how it's installed and behaves. Think about which manifest properties directly relate to these technologies.

3. **Analyze the provided code snippets:** The snippets showcase tests for the `shortcuts` and `file_handlers` manifest properties. Examine what aspects are being tested:
    - **Presence/absence of required fields:**  Testing if the parser correctly identifies missing `name` or `url` in shortcuts.
    - **Data types:** Verifying if the parser enforces the correct data types (strings, arrays, objects).
    - **Value constraints:** Checking for empty strings, URL validity, and limits on the number of shortcuts.
    - **Whitespace handling:**  Observing how the parser deals with leading/trailing whitespace.
    - **URL resolution and scope:** Understanding how URLs are resolved relative to the manifest and the document, and the role of the `scope` property.
    - **Error handling:** Identifying how errors are reported and counted.
    - **Feature flags:** Recognizing the use of feature flags (like `kFileHandlingIcons`).

4. **Formulate examples and scenarios:** Based on the code, create concrete examples of valid and invalid manifest snippets and predict the parsing outcome.

5. **Consider user/developer errors:** Think about common mistakes developers might make when writing manifest files and how the parser helps catch them.

6. **Trace user actions:** Imagine the steps a user takes to trigger the parsing logic. This usually involves the browser fetching and processing a manifest file linked in an HTML page.

7. **Summarize the functionality (part 3):** Focus on the specific aspects covered in the provided code, which primarily concerns the parsing of `shortcuts` and `file_handlers`.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript, html, css的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第3部分，共8部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response.

这个C++源代码文件 `manifest_parser_unittest.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 Web App Manifest 文件的解析器 (`ManifestParser`). 作为第 3 部分，它主要关注了对 manifest 文件中 **shortcuts (快捷方式)** 和 **file_handlers (文件处理器)** 属性的解析逻辑进行单元测试。

以下是其功能的详细说明：

**1. 功能概述:**

* **测试 Shortcuts 属性解析:**  这部分测试验证了 `ManifestParser` 正确解析 manifest 文件中 `shortcuts` 数组的能力。它涵盖了以下几个方面：
    * **基本结构:** 测试了 `shortcuts` 数组存在和不存在的情况，以及数组中元素是否为对象。
    * **必要属性验证:** 检查了每个 shortcut 对象是否包含 `name` 和 `url` 属性，以及当这些属性缺失或为空时的处理方式。
    * **数据类型验证:** 确保 `name`、`short_name`、`description` 和 `url` 属性的值是字符串类型。
    * **值规范化:**  测试了对 `name`、`short_name` 和 `description` 属性值进行去除首尾空格的处理。
    * **URL 解析和作用域:**  验证了 `url` 属性的解析是否基于 manifest 文件的 URL 进行，并且是否考虑了 manifest 的 `scope` 属性，确保 shortcut 的 URL 在作用域内。
    * **Icons 解析:** 测试了 shortcut 中 `icons` 数组的解析，包括空数组、空对象以及包含有效 `src` 的 icon 对象的解析。
    * **数量限制:**  验证了对 `shortcuts` 数组中元素数量的限制（例如，只解析前 10 个有效的 shortcut）。
* **测试 File Handlers 属性解析:** 这部分测试验证了 `ManifestParser` 正确解析 manifest 文件中 `file_handlers` 数组的能力。它涵盖了以下几个方面：
    * **基本结构:** 测试了 `file_handlers` 数组存在和不存在的情况，以及数组中元素是否为对象。
    * **必要属性验证:** 检查了每个 file handler 对象是否包含 `action` 和 `accept` 属性。
    * **数据类型验证:**  确保 `action` 是字符串类型，`accept` 是对象类型。
    * **URL 解析和作用域:**  验证了 `action` 属性的 URL 解析是否在 manifest 的作用域内。
    * **Accept 属性解析:**  详细测试了 `accept` 属性的解析，包括：
        * `accept` 的值必须是对象。
        * MIME 类型作为键，接受的文件扩展名作为值（字符串或字符串数组）。
        * 验证文件扩展名必须以 `.` 开头。
        * 处理无效的 MIME 类型和带有参数的 MIME 类型。
        * 测试接受单个字符串或字符串数组作为文件扩展名的解析。
    * **数量限制:**  验证了对 file handlers 中文件扩展名总数的限制。

**2. 与 JavaScript, HTML, CSS 的关系:**

Web App Manifest 文件是用 JSON 格式编写的，它描述了 Web 应用程序的元数据，这些元数据会被浏览器用来更好地集成 Web 应用到用户的操作系统中。

* **JavaScript:**  当 Web 应用运行时，JavaScript 代码可以通过 Web API（如 `navigator.getInstalledRelatedApps()`）访问 manifest 中的信息，包括 `shortcuts` 和 `file_handlers`。例如，开发者可以使用 `shortcuts` 信息来动态创建应用内的快捷方式。对于 `file_handlers`，当用户尝试打开特定类型的文件时，操作系统可能会调用注册了相应文件处理器的 Web 应用。
    * **假设输入 (Manifest):**
      ```json
      {
        "name": "My App",
        "shortcuts": [
          {
            "name": "New Document",
            "url": "/new"
          }
        ]
      }
      ```
    * **JavaScript 输出 (可能的操作):**  JavaScript 代码可以读取到 "New Document" 快捷方式，并在用户点击时导航到 `/new` 页面。

* **HTML:**  HTML 文件通过 `<link rel="manifest" href="manifest.json">` 标签声明了 manifest 文件的位置。浏览器会解析 manifest 文件，并根据其中的信息来调整 Web 应用的行为和外观。`shortcuts` 可以在操作系统层面创建应用的快捷方式入口，而 `file_handlers` 则允许 Web 应用响应特定类型的文件打开事件。
    * **举例:** 当 manifest 中定义了 `shortcuts`，操作系统可能会在用户的应用启动器或桌面创建相应的快捷方式，用户点击这些快捷方式可以直接跳转到应用内的特定功能页面，无需先打开应用的主页。

* **CSS:**  虽然 manifest 文件本身不包含 CSS 代码，但 manifest 中的某些属性可能会间接地影响到 CSS 的使用。例如，`display` 属性可以控制 Web 应用在启动时的显示模式（如 `standalone`、`fullscreen` 等），这会影响到浏览器提供的用户界面元素，从而间接影响到应用的整体布局和 CSS 的呈现。此外，`icons` 属性定义的图标会被浏览器用于各种场景，例如添加到桌面或应用启动器，这些图标的视觉效果会受到 CSS 的影响。

**3. 逻辑推理的假设输入与输出:**

* **假设输入 (Manifest - Shortcuts 数量限制):**
  ```json
  {
    "shortcuts": [
      {"name": "1", "url": "1"},
      {"name": "2", "url": "2"},
      {"name": "3", "url": "3"},
      {"name": "4", "url": "4"},
      {"name": "5", "url": "5"},
      {"name": "6", "url": "6"},
      {"name": "7", "url": "7"},
      {"name": "8", "url": "8"},
      {"name": "9", "url": "9"},
      {"name": "10", "url": "10"},
      {"name": "11", "url": "11"}
    ]
  }
  ```
* **预期输出 (解析结果和错误):**  `manifest->shortcuts` 数组将包含前 10 个 shortcut 对象，并且会记录一个错误，指示 `shortcuts` 属性包含超过 10 个有效元素，只解析了前 10 个。

* **假设输入 (Manifest - File Handlers 错误的 MIME 类型):**
  ```json
  {
    "file_handlers": [
      {
        "name": "Image Viewer",
        "action": "/view",
        "accept": {
          "image_png": ".png"
        }
      }
    ]
  }
  ```
* **预期输出 (解析结果和错误):**  `manifest->file_handlers` 数组为空，并且会记录一个错误，指示 "image_png" 是一个无效的 MIME 类型。

**4. 涉及用户或编程常见的使用错误:**

* **忘记在 shortcut 中添加 `name` 或 `url`:**  这是最常见的错误，用户可能只定义了部分属性，导致快捷方式无法正常工作。
    * **例子:**
      ```json
      {
        "shortcuts": [
          { "url": "/settings" } // 缺少 name
        ]
      }
      ```
      **错误信息:** `property 'name' of 'shortcut' not present.`
* **在 shortcut 的 `url` 中使用了错误的 URL 格式或不在作用域内的 URL:**  这会导致快捷方式链接到错误的位置或无法访问。
    * **例子:**
      ```json
      {
        "shortcuts": [
          { "name": "Settings", "url": "settings" } // 相对 URL，但 manifest URL 可能不是在根目录
        ]
      }
      ```
      如果 manifest 文件位于 `http://example.com/app/manifest.json`，但期望的路径是 `http://example.com/settings`，则会出错。
    * **例子 (超出作用域):**
      ```json
      {
        "scope": "/app/",
        "shortcuts": [
          { "name": "External Link", "url": "/external" }
        ]
      }
      ```
      如果 `/external` 不在 `/app/` 的作用域内，则会报错。
* **在 file_handlers 的 `accept` 属性中使用了不以 `.` 开头的文件扩展名:** 这是 `file_handlers` 中常见的错误。
    * **例子:**
      ```json
      {
        "file_handlers": [
          {
            "name": "Text Editor",
            "action": "/edit",
            "accept": {
              "text/plain": "txt"
            }
          }
        ]
      }
      ```
      **错误信息:** `property 'accept' file extension ignored, must start with a '.'.`
* **在 file_handlers 的 `accept` 属性中使用了无效的 MIME 类型:**  会导致浏览器无法正确识别文件类型。
    * **例子:**
      ```json
      {
        "file_handlers": [
          {
            "name": "Image Viewer",
            "action": "/view",
            "accept": {
              "imagepng": ".png"
            }
          }
        ]
      }
      ```
      **错误信息:** `invalid MIME type: imagepng`

**5. 用户操作如何一步步的到达这里 (调试线索):**

1. **开发者创建或修改 Web App Manifest 文件:**  开发者在其 Web 应用的根目录或指定路径下创建或编辑 `manifest.json` 文件，并在其中定义了 `shortcuts` 和 `file_handlers` 属性。
2. **在 HTML 文件中声明 Manifest:** 开发者在 HTML 文件的 `<head>` 部分使用 `<link rel="manifest" href="manifest.json">` 标签来声明 manifest 文件的位置。
3. **用户访问该 Web 应用:** 用户通过浏览器访问部署了该 Web 应用的网站。
4. **浏览器解析 HTML:**  浏览器加载 HTML 文件并解析其中的标签。
5. **浏览器发现 Manifest 声明:** 浏览器找到 `<link rel="manifest">` 标签。
6. **浏览器请求 Manifest 文件:** 浏览器向服务器请求 `href` 属性指定的 manifest 文件（例如 `manifest.json`）。
7. **服务器响应 Manifest 文件:** 服务器返回 manifest 文件的内容。
8. **Blink 引擎的 ManifestParser 被调用:**  Blink 引擎中的 `ManifestParser` 类会被调用来解析下载的 manifest 文件内容。
9. **`manifest_parser_unittest.cc` 中相应的测试被执行 (开发阶段):** 在 Chromium 的开发或测试阶段，开发者会运行单元测试，其中包括 `manifest_parser_unittest.cc` 中的测试，以确保 `ManifestParser` 正确地解析 manifest 文件，包括 `shortcuts` 和 `file_handlers` 属性。如果解析逻辑有任何错误，这里的测试会失败，为开发者提供调试线索。

**6. 第 3 部分功能归纳:**

作为第 3 部分，这个代码文件主要专注于测试 `ManifestParser` 组件对 Web App Manifest 文件中以下两个关键属性的解析逻辑：

* **`shortcuts`**:  验证了对应用程序快捷方式的解析，包括必要属性的检查、数据类型验证、URL 解析和作用域检查，以及对图标信息的处理和快捷方式数量的限制。
* **`file_handlers`**: 验证了对文件处理器的解析，包括必要属性的检查、数据类型验证、URL 作用域检查，以及对 `accept` 属性中 MIME 类型和文件扩展名的详细解析规则的测试，以及对文件扩展名总数的限制。

总而言之，这个文件通过大量的单元测试用例，细致地验证了 `ManifestParser` 在处理 `shortcuts` 和 `file_handlers` 属性时的正确性和健壮性，确保了 Chromium 浏览器能够按照 Web 标准准确地理解和应用 manifest 文件中定义的这些功能。

Prompt: 
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
);
  }

  // Smoke test: shortcut with invalid name and url, it will not be present in
  // the list.
  {
    auto& manifest =
        ParseManifest(R"({ "shortcuts": [ { "shortcuts": [] } ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[0]);
  }

  // Smoke test: shortcut with no name, it will not be present in the list.
  {
    auto& manifest = ParseManifest(R"({ "shortcuts": [ { "url": "" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' not present.", errors()[0]);
  }

  // Smoke test: shortcut with no url, it will not be present in the list.
  {
    auto& manifest = ParseManifest(R"({ "shortcuts": [ { "name": "" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[0]);
  }

  // Smoke test: shortcut with empty name, and empty src, will not be present in
  // the list.
  {
    auto& manifest =
        ParseManifest(R"({ "shortcuts": [ { "name": "", "url": "" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' is an empty string.", errors()[0]);
  }

  // Smoke test: shortcut with valid (non-empty) name and src, will be present
  // in the list.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [{ "name": "New Post", "url": "compose" }]
        })");
    EXPECT_FALSE(manifest->shortcuts.empty());

    auto& shortcuts = manifest->shortcuts;
    EXPECT_EQ(shortcuts.size(), 1u);
    EXPECT_EQ(shortcuts[0]->name, "New Post");
    EXPECT_EQ(shortcuts[0]->url.GetString(), "http://foo.com/compose");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Validate only the first 10 shortcuts are parsed. The following manifest
  // specifies 11 shortcuts, so the last one should not be in the result.
  {
    auto& manifest = ParseManifest(
        R"({
          "shortcuts": [
            {
              "name": "1",
              "url": "1"
            },
            {
              "name": "2",
              "url": "2"
            },
            {
              "name": "3",
              "url": "3"
            },
            {
              "name": "4",
              "url": "4"
            },
            {
              "name": "5",
              "url": "5"
            },
            {
              "name": "6",
              "url": "6"
            },
            {
              "name": "7",
              "url": "7"
            },
            {
              "name": "8",
              "url": "8"
            },
            {
              "name": "9",
              "url": "9"
            },
            {
              "name": "10",
              "url": "10"
            },
            {
              "name": "11",
              "url": "11"
            }
          ]
        })");

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'shortcuts' contains more than 10 valid elements, "
        "only the first 10 are parsed.",
        errors()[0]);

    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    auto& shortcuts = manifest->shortcuts;
    EXPECT_EQ(shortcuts.size(), 10u);
    EXPECT_EQ(shortcuts[9]->name, "10");
    EXPECT_EQ(shortcuts[9]->url.GetString(), "http://foo.com/10");
  }
}

TEST_F(ManifestParserTest, ShortcutNameParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "foo", "url": "NameParseTest" } ]
        })");
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_EQ(manifest->shortcuts[0]->name, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "  foo  ", "url": "NameParseTest"
        } ] })");
    ASSERT_EQ(manifest->shortcuts[0]->name, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if shortcut->name isn't present.
  {
    auto& manifest =
        ParseManifest(R"({ "shortcuts": [ {"url": "NameParseTest" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' not present.", errors()[0]);
  }

  // Don't parse if shortcut->name isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": {}, "url": "NameParseTest" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if shortcut->name isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": 42, "url": "NameParseTest" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if shortcut->name is an empty string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "", "url": "NameParseTest" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' of 'shortcut' is an empty string.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShortcutShortNameParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "ShortNameParseTest", "short_name":
        "foo", "url": "ShortNameParseTest" } ] })");
    ASSERT_EQ(manifest->shortcuts[0]->short_name, "foo");
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Shortcut member is parsed when no short_name is present
  {
    auto& manifest =
        ParseManifest(R"({ "shortcuts": [ {"name": "ShortNameParseTest", "url":
        "ShortNameParseTest" } ] })");
    ASSERT_TRUE(manifest->shortcuts[0]->short_name.IsNull());
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "ShortNameParseTest", "short_name":
        "  foo  ", "url": "ShortNameParseTest" } ] })");
    ASSERT_EQ(manifest->shortcuts[0]->short_name, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse short_name if it isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "ShortNameParseTest", "short_name":
        {}, "url": "ShortNameParseTest" } ] })");
    ASSERT_TRUE(manifest->shortcuts[0]->short_name.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'short_name' of 'shortcut' ignored, type string expected.",
        errors()[0]);
  }

  // Don't parse short_name if it isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "ShortNameParseTest", "short_name":
        42, "url": "ShortNameParseTest" } ] })");
    ASSERT_TRUE(manifest->shortcuts[0]->short_name.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'short_name' of 'shortcut' ignored, type string expected.",
        errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShortcutDescriptionParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {
          "name": "DescriptionParseTest",
          "description": "foo",
          "url": "DescriptionParseTest" } ]
        })");
    ASSERT_EQ(manifest->shortcuts[0]->description, "foo");
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Shortcut member is parsed when no description is present
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "DescriptionParseTest", "url":
        "DescriptionParseTest" } ] })");
    ASSERT_TRUE(manifest->shortcuts[0]->description.IsNull());
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {
          "name": "DescriptionParseTest",
          "description": "  foo  ",
          "url": "DescriptionParseTest" } ]
        })");
    ASSERT_EQ(manifest->shortcuts[0]->description, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse description if it isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {
          "name": "DescriptionParseTest",
          "description": {},
          "url": "DescriptionParseTest" } ]
        })");
    ASSERT_TRUE(manifest->shortcuts[0]->description.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'description' of 'shortcut' ignored, type string expected.",
        errors()[0]);
  }

  // Don't parse description if it isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {
          "name": "DescriptionParseTest",
          "description": 42,
          "url": "DescriptionParseTest" } ]
        })");
    ASSERT_TRUE(manifest->shortcuts[0]->description.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'description' of 'shortcut' ignored, type string expected.",
        errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShortcutUrlParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url": "foo" } ]
        })");
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_EQ(manifest->shortcuts[0]->url, KURL(DefaultDocumentUrl(), "foo"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test. Don't parse (with an error) when url is not present.
  {
    auto& manifest = ParseManifest(R"({ "shortcuts": [ { "name": "" } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[0]);
  }

  // Whitespaces.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url": "   foo   " } ] })");
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_EQ(manifest->shortcuts[0]->url, KURL(DefaultDocumentUrl(), "foo"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if url isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url": {} } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, type string expected.", errors()[0]);
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[1]);
  }

  // Don't parse if url isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url": 42 } ] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, type string expected.", errors()[0]);
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[1]);
  }

  // Resolving has to happen based on the manifest_url.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url": "foo" } ]
        })",
        KURL("http://foo.com/landing/manifest.json"), DefaultDocumentUrl());
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_EQ(manifest->shortcuts[0]->url.GetString(),
              "http://foo.com/landing/foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Shortcut url should have same origin as the document url.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "shortcuts": [ {"name": "UrlParseTest", "url":
        "http://bar.com/landing" } ]
        })",
        KURL("http://foo.com/landing/manifest.json"), DefaultDocumentUrl());
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, should be within scope of the manifest.",
              errors()[0]);
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[1]);
  }

  // Shortcut url should be within the manifest scope.
  // The scope will be http://foo.com/landing.
  // The shortcut_url will be http://foo.com/shortcut which is in not in scope.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/landing", "shortcuts": [ {"name":
        "UrlParseTest", "url": "shortcut" } ] })",
        KURL("http://foo.com/manifest.json"),
        KURL("http://foo.com/landing/index.html"));
    EXPECT_TRUE(manifest->shortcuts.empty());
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/landing");
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, should be within scope of the manifest.",
              errors()[0]);
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[1]);
  }

  // Shortcut url should be within the manifest scope.
  // The scope will be http://foo.com/land.
  // The shortcut_url will be http://foo.com/land/shortcut which is in scope.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/land", "start_url":
        "http://foo.com/land/landing.html", "shortcuts": [ {"name":
        "UrlParseTest", "url": "shortcut" } ] })",
        KURL("http://foo.com/land/manifest.json"),
        KURL("http://foo.com/index.html"));
    EXPECT_FALSE(manifest->shortcuts.empty());
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/land");
    EXPECT_EQ(manifest->shortcuts[0]->url.GetString(),
              "http://foo.com/land/shortcut");
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ShortcutIconsParseRules) {
  // Smoke test: if no icons, shortcut->icons has no value.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_TRUE(manifest->shortcuts[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if empty icon, shortcut->icons has no value.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [{}] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_TRUE(manifest->shortcuts[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: icon with invalid src, shortcut->icons has no value.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [{ "icons": [] }] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_TRUE(manifest->shortcuts[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if icon with empty src, it will be present in shortcut->icons.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [ { "src": "" } ] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_FALSE(manifest->shortcuts[0]->icons.empty());

    auto& icons = manifest->shortcuts[0]->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/manifest.json");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if one icon with valid src, it will be present in
  // shortcut->icons.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [ { "src": "foo.jpg" } ] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_FALSE(manifest->shortcuts[0]->icons.empty());
    auto& icons = manifest->shortcuts[0]->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if >1 icon with valid src, it will be present in
  // shortcut->icons.
  {
    auto& manifest = ParseManifest(
        R"({ "shortcuts": [ {"name": "IconParseTest", "url": "foo",
        "icons": [ {"src": "foo.jpg"}, {"src": "bar.jpg"} ] } ] })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->shortcuts.empty());
    EXPECT_FALSE(manifest->shortcuts[0]->icons.empty());
    auto& icons = manifest->shortcuts[0]->icons;
    EXPECT_EQ(icons.size(), 2u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_EQ(icons[1]->src.GetString(), "http://foo.com/bar.jpg");
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, FileHandlerParseRules) {
  base::test::ScopedFeatureList feature_list(
      blink::features::kFileHandlingIcons);
  // Does not contain file_handlers field.
  {
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // file_handlers is not an array.
  {
    auto& manifest = ParseManifest(R"({ "file_handlers": { } })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'file_handlers' ignored, type array expected.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Contains file_handlers field but no file handlers.
  {
    auto& manifest = ParseManifest(R"({ "file_handlers": [ ] })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entries must be objects.
  {
    auto& manifest = ParseManifest(R"({
          "file_handlers": [
            "hello world"
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("FileHandler ignored, type object expected.", errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry without an action is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "accept": {
                "image/png": [
                  ".png"
                ]
              }
            }
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("FileHandler ignored. Property 'action' is invalid.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry with an action on a different origin is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "https://example.com/files",
              "accept": {
                "image/png": [
                  ".png"
                ]
              }
            }
          ]
        })");
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'action' ignored, should be within scope of the manifest.",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'action' is invalid.",
              errors()[1]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry with an action outside of the manifest scope is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "start_url": "/app/",
          "scope": "/app/",
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": [
                  ".png"
                ]
              }
            }
          ]
        })");
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'action' ignored, should be within scope of the manifest.",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'action' is invalid.",
              errors()[1]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry without a name is valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": [
                  ".png"
                ]
              }
            }
          ]
        })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(1u, manifest->file_handlers.size());
  }

  // Entry without an icon is valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "action": "/files",
              "accept": {
                "image/png": [
                  ".png"
                ]
              }
            }
          ]
        })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(1u, manifest->file_handlers.size());
  }

  // Entry without an accept is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files"
            }
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry where accept is not an object is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": "image/png"
            }
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry where accept extensions are not an array or string is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": {}
              }
            }
          ]
        })");
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'accept' type ignored. File extensions must be type array or "
        "type string.",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[1]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry where accept extensions are not an array or string is invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": 3
              }
            }
          ]
        })");
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'accept' type ignored. File extensions must be type array or "
        "type string.",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[1]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Entry with an empty list of extensions is not valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": []
              }
            }
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->file_handlers.size());
  }

  // Extensions that do not start with a '.' are invalid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": [
                  "png"
                ]
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'accept' file extension ignored, must start with a '.'.",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[1]);
    ASSERT_EQ(0u, file_handlers.size());
  }

  // Invalid MIME types and those with parameters are stripped.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "Foo",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image_png": ".png",
                "foo/bar": ".foo",
                "application/foobar;parameter=25": ".foobar",
                "application/its+xml": ".itsml"
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(3u, GetErrorCount());
    EXPECT_EQ("invalid MIME type: image_png", errors()[0]);
    EXPECT_EQ("invalid MIME type: foo/bar", errors()[1]);
    EXPECT_EQ("invalid MIME type: application/foobar;parameter=25",
              errors()[2]);
    ASSERT_EQ(1u, file_handlers.size());

    EXPECT_EQ("Foo", file_handlers[0]->name);
    EXPECT_EQ("http://foo.com/foo.jpg",
              file_handlers[0]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/files"), file_handlers[0]->action);
    ASSERT_EQ(1U, file_handlers[0]->accept.size());
    ASSERT_TRUE(file_handlers[0]->accept.Contains("application/its+xml"));
    EXPECT_EQ(0u, file_handlers[0]
                      ->accept.find("application/its+xml")
                      ->value.Contains(".foobar"));
  }

  // Extensions specified as a single string is valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, file_handlers.size());

    EXPECT_EQ("name", file_handlers[0]->name);
    EXPECT_EQ("http://foo.com/foo.jpg",
              file_handlers[0]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/files"), file_handlers[0]->action);
    ASSERT_TRUE(file_handlers[0]->accept.Contains("image/png"));
    ASSERT_EQ(1u, file_handlers[0]->accept.find("image/png")->value.size());
    EXPECT_EQ(".png", file_handlers[0]->accept.find("image/png")->value[0]);
  }

  // An array of extensions is valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "name",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/jpg": [
                  ".jpg",
                  ".jpeg"
                ]
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, file_handlers.size());

    EXPECT_EQ("name", file_handlers[0]->name);
    EXPECT_EQ("http://foo.com/foo.jpg",
              file_handlers[0]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/files"), file_handlers[0]->action);
    ASSERT_TRUE(file_handlers[0]->accept.Contains("image/jpg"));
    ASSERT_EQ(2u, file_handlers[0]->accept.find("image/jpg")->value.size());
    EXPECT_EQ(".jpg", file_handlers[0]->accept.find("image/jpg")->value[0]);
    EXPECT_EQ(".jpeg", file_handlers[0]->accept.find("image/jpg")->value[1]);
  }

  // Multiple mime types are valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "Image",
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": ".png",
                "image/jpg": [
                  ".jpg",
                  ".jpeg"
                ]
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, file_handlers.size());

    EXPECT_EQ("Image", file_handlers[0]->name);
    EXPECT_EQ("http://foo.com/foo.jpg",
              file_handlers[0]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/files"), file_handlers[0]->action);

    ASSERT_TRUE(file_handlers[0]->accept.Contains("image/jpg"));
    ASSERT_EQ(2u, file_handlers[0]->accept.find("image/jpg")->value.size());
    EXPECT_EQ(".jpg", file_handlers[0]->accept.find("image/jpg")->value[0]);
    EXPECT_EQ(".jpeg", file_handlers[0]->accept.find("image/jpg")->value[1]);

    ASSERT_TRUE(file_handlers[0]->accept.Contains("image/png"));
    ASSERT_EQ(1u, file_handlers[0]->accept.find("image/png")->value.size());
    EXPECT_EQ(".png", file_handlers[0]->accept.find("image/png")->value[0]);
  }

  // file_handlers with multiple entries is valid.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "Graph",
              "icons": [{ "src": "graph.jpg" }],
              "action": "/graph",
              "accept": {
                "text/svg+xml": [
                  ".svg",
                  ".graph"
                ]
              }
            },
            {
              "name": "Raw",
              "icons": [{ "src": "raw.jpg" }],
              "action": "/raw",
              "accept": {
                "text/csv": ".csv"
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(2u, file_handlers.size());

    EXPECT_EQ("Graph", file_handlers[0]->name);
    EXPECT_EQ("http://foo.com/graph.jpg",
              file_handlers[0]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/graph"), file_handlers[0]->action);
    ASSERT_TRUE(file_handlers[0]->accept.Contains("text/svg+xml"));
    ASSERT_EQ(2u, file_handlers[0]->accept.find("text/svg+xml")->value.size());
    EXPECT_EQ(".svg", file_handlers[0]->accept.find("text/svg+xml")->value[0]);
    EXPECT_EQ(".graph",
              file_handlers[0]->accept.find("text/svg+xml")->value[1]);

    EXPECT_EQ("Raw", file_handlers[1]->name);
    EXPECT_EQ("http://foo.com/raw.jpg",
              file_handlers[1]->icons[0]->src.GetString());
    EXPECT_EQ(KURL("http://foo.com/raw"), file_handlers[1]->action);
    ASSERT_TRUE(file_handlers[1]->accept.Contains("text/csv"));
    ASSERT_EQ(1u, file_handlers[1]->accept.find("text/csv")->value.size());
    EXPECT_EQ(".csv", file_handlers[1]->accept.find("text/csv")->value[0]);
  }

  // file_handlers limits the total number of file extensions. Everything after
  // and including the file handler that hits the extension limit
  {
    ManifestParser::SetFileHandlerExtensionLimitForTesting(5);
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "name": "Raw",
              "action": "/raw",
              "accept": {
                "text/csv": ".csv"
              }
            },
            {
              "name": "Graph",
              "action": "/graph",
              "accept": {
                "text/svg+xml": [
                  ".graph1",
                  ".graph2",
                  ".graph3",
                  ".graph4",
                  ".graph5",
                  ".graph6"
                ]
              }
            },
            {
              "name": "Data",
              "action": "/data",
              "accept": {
                "text/plain": [
                  ".data"
                ]
              }
            }
          ]
        })");
    auto& file_handlers = manifest->file_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'accept': too many total file extensions, ignoring "
        "extensions starting from \".graph5\"",
        errors()[0]);
    EXPECT_EQ("FileHandler ignored. Property 'accept' is invalid.",
              errors()[1]);

    ASSERT_EQ(2u, file_handlers.size());

    EXPECT_EQ("Raw", file_handlers[0
"""


```