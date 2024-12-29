Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for the Blink rendering engine. The file `manifest_parser_unittest.cc` is specifically testing the parsing of web app manifest files.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `manifest_parser_unittest.cc` strongly suggests this file tests the parsing of web app manifests. The code itself confirms this by using terms like "ParseManifest" and inspecting the resulting `manifest` object.

2. **Analyze the structure:** The code is organized into multiple `TEST_F` blocks within a `ManifestParserTest` fixture. Each `TEST_F` focuses on testing a specific aspect of manifest parsing, such as the parsing of `share_target`, `related_applications`, `theme_color`, `background_color`, etc.

3. **Examine the content of each test case:**  Within each `TEST_F`, there are multiple sub-blocks (often enclosed in curly braces `{}`) that represent individual test scenarios. Each scenario usually:
    * Defines an input manifest string (typically JSON).
    * Calls a parsing function (like `ParseManifestWithURLs` or `ParseManifest`).
    * Makes assertions about the parsed `manifest` object using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, etc. These assertions verify that the parsing logic behaves as expected for different inputs (valid, invalid, missing fields, etc.).
    * Checks for expected error messages using `GetErrorCount()` and `errors()`.

4. **Identify key manifest properties being tested:**  By looking at the test case names and the properties being accessed in the assertions (e.g., `manifest->share_target`, `manifest->related_applications`, `manifest->theme_color`),  we can identify the specific manifest features being validated.

5. **Infer relationships to web technologies:**  Web app manifests are crucial for Progressive Web Apps (PWAs) and define metadata about the application. Therefore, the properties being tested directly relate to features users and developers interact with in the context of PWAs.
    * `share_target`: Enables web sharing functionality, linking to HTML form submissions.
    * `related_applications`: Allows linking to native apps.
    * `theme_color` and `background_color`:  Control the visual appearance of the app.

6. **Look for examples of input/output and error handling:** The test cases provide explicit examples of:
    * **Valid input:** Manifest snippets that should parse correctly.
    * **Invalid input:** Manifest snippets with errors (incorrect types, missing required fields, invalid values) and the expected error messages.
    * **Default behavior:**  How the parser handles missing optional fields (e.g., default values for `method` and `enctype` in `share_target`).

7. **Consider the user perspective:**  The tests implicitly demonstrate how developers might make mistakes when creating manifest files and how the parser detects and reports those errors. Examples include:
    * Incorrect data types for manifest properties.
    * Missing required properties.
    * Invalid values for specific properties (e.g., invalid MIME types in `share_target`).

8. **Think about debugging:**  Unit tests serve as excellent debugging tools. If a manifest isn't behaving as expected, examining these tests can provide insights into potential parsing issues. The tests show how different manifest structures are interpreted, which can help narrow down the cause of a problem.

9. **Synthesize the findings into a summary:** Combine the observations into a concise description of the file's functionality, highlighting its role in testing manifest parsing, its relation to web technologies, examples of tested scenarios, and its relevance for developers and debugging. Specifically address the prompt's requirements about JavaScript, HTML, CSS, logical reasoning, user errors, and debugging.

10. **Address the "part 6 of 8" instruction:** Acknowledge that this is part of a larger test suite and therefore focuses on a subset of manifest parsing features.

By following these steps, we can generate a comprehensive and informative answer that addresses all aspects of the user's request.
这是名为 `manifest_parser_unittest.cc` 的 Chromium Blink 引擎源代码文件的一部分，专门用于测试 Web App Manifest 文件的解析功能。从提供的代码片段来看，这部分着重于测试 `share_target` 属性的解析规则，以及少量其他属性（`related_applications`，`prefer_related_applications`，`theme_color`，`background_color`）。

**它的功能归纳如下：**

* **测试 `share_target` 属性的解析:**  这部分代码详细测试了 `manifest` 文件中 `share_target` 属性的各种情况，包括：
    * `action` (分享的目标 URL) 的解析。
    * `method` (请求方法，GET 或 POST) 的解析和默认值处理。
    * `enctype` (编码类型) 的解析和默认值处理，以及与 `method` 的关联性。
    * `params` (分享时传递的参数) 的解析，包括 `title` 和 `files` 数组。
    * 对 `files` 数组中的 `name` 和 `accept` 属性的解析和校验，特别是 `accept` 字段中 MIME 类型的有效性。
    * 处理各种无效的 `method` 和 `enctype` 值，以及在不符合规范时的错误提示。
* **测试 `related_applications` 属性的解析:** 测试了相关应用信息的解析，包括 `platform`、`url` 和 `id` 属性的校验和处理，以及无效或缺失属性时的忽略行为。
* **测试 `prefer_related_applications` 属性的解析:**  测试了该布尔类型属性的解析，以及非布尔类型值时的错误处理。
* **测试 `theme_color` 属性的解析:** 测试了主题颜色的解析，包括各种有效的 CSS 颜色格式，以及无效格式时的错误处理。
* **测试 `background_color` 属性的解析:** 测试了背景颜色的解析，与 `theme_color` 类似，测试了各种有效的 CSS 颜色格式和无效格式的处理。

**与 javascript, html, css 的功能关系：**

* **JavaScript:** Web App Manifest 文件是为 Progressive Web Apps (PWAs) 提供元数据的重要组成部分。JavaScript 代码会读取和利用 manifest 文件中的信息，例如 `share_target` 用于处理 Web Share API 的请求，允许用户从 Web 应用分享内容到其他应用。
    * **举例:** 当用户在 PWA 中触发分享操作时，浏览器会读取 manifest 文件中的 `share_target` 信息，根据配置的 `action`、`method`、`enctype` 和 `params` 构建一个 HTML 表单，并将用户选择分享的数据填充到表单中，最终提交到指定的 URL。
* **HTML:** Manifest 文件通过 HTML 的 `<link>` 标签引入，例如 `<link rel="manifest" href="/manifest.json">`。`share_target` 的 `action` 属性指定了一个 HTML 页面作为分享的目标。
    * **举例:**  `share_target` 的 `action` 可能指向一个 Web 应用程序内的特定页面，该页面接收分享的数据并进行处理和展示。
* **CSS:** `theme_color` 和 `background_color` 属性直接影响浏览器的 UI，例如浏览器地址栏的颜色和启动画面的背景色。
    * **举例:** 如果 manifest 文件中设置了 `"theme_color": "#FF0000"`, 那么在支持 PWA 的浏览器中，该 PWA 的地址栏颜色可能会变为红色。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
  ```json
  {
    "share_target": {
      "action": "/share",
      "method": "POST",
      "enctype": "multipart/form-data",
      "params": {
        "title": "shared_title",
        "text": "shared_text",
        "url": "shared_url",
        "files": [
          { "name": "my_image", "accept": ["image/png", "image/jpeg"] }
        ]
      }
    }
  }
  ```
* **预期输出 (部分):**
    * `manifest->share_target.has_value()` 为 `true`。
    * `manifest->share_target->action` 等于 "/share"。
    * `manifest->share_target->method` 等于 `mojom::blink::ManifestShareTarget::Method::kPost`。
    * `manifest->share_target->enctype` 等于 `mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData`。
    * `manifest->share_target->params->title` 等于 "shared_title"。
    * `manifest->share_target->params->files.has_value()` 为 `true`。
    * `manifest->share_target->params->files->size()` 等于 1。
    * `manifest->share_target->params->files[0]->name` 等于 "my_image"。
    * `manifest->share_target->params->files[0]->accept` 包含 "image/png" 和 "image/jpeg"。
    * `GetErrorCount()` 为 0。

**用户或编程常见的使用错误举例说明:**

* **`share_target` 中 `method` 和 `enctype` 的不匹配:**
    * **错误:**  设置 `"method": "GET"` 但同时定义了 `files` 数组。
    * **结果:** 解析器会报错，因为 GET 请求通常不用于上传文件，multipart/form-data 主要用于 POST 请求。错误信息会提示 "invalid enctype for GET method. Only application/x-www-form-urlencoded is allowed."
* **`share_target` 中 `files` 的 `accept` 属性包含无效的 MIME 类型:**
    * **错误:** 设置 `"accept": ["image/wrong"]`。
    * **结果:** 解析器会报错，提示 "invalid mime type inside files."，因为 "image/wrong" 不是一个有效的 MIME 类型。
* **`related_applications` 缺少必要的属性:**
    * **错误:**  定义一个 related application 对象，但缺少 `"platform"` 属性。
    * **结果:** 解析器会忽略该 related application，并报错 "'platform' is a required field, related application ignored."
* **`theme_color` 或 `background_color` 使用了无效的颜色格式:**
    * **错误:**  设置 `"theme_color": "not a color"`。
    * **结果:** 解析器会忽略该属性，并报错 "property 'theme_color' ignored, 'not a color' is not a valid color."

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者创建或修改 Web App Manifest 文件 (`manifest.json`)**:  开发者在他们的网站根目录或者指定的路径下创建或修改 `manifest.json` 文件，以配置 PWA 的各种行为，包括分享目标、相关应用、主题颜色等。
2. **浏览器请求 manifest 文件**: 当用户访问一个声明了 manifest 文件的网页时，浏览器会解析 HTML，发现 `<link rel="manifest" href="...">` 标签，并向服务器请求该 manifest 文件。
3. **Blink 引擎解析 manifest 文件**:  Chromium 的 Blink 引擎接收到 manifest 文件的内容后，会调用相应的解析代码（包括 `manifest_parser.cc` 中实现的逻辑）来解析 JSON 格式的 manifest 文件。
4. **`manifest_parser_unittest.cc` 的作用**: 在开发和测试 Blink 引擎的过程中，为了确保 manifest 文件能被正确解析，开发者会编写单元测试，例如 `manifest_parser_unittest.cc`。这些测试会模拟各种可能的 manifest 文件内容（包括正确的和错误的），并断言解析结果是否符合预期。

**调试线索:** 如果在实际应用中发现 manifest 文件的解析行为不符合预期，例如分享功能无法正常工作，或者主题颜色没有生效，开发者可以：

* **检查 manifest 文件内容**:  确认 `manifest.json` 文件的语法是否正确，属性名称和值是否符合规范。
* **查看浏览器开发者工具**:  现代浏览器通常会在开发者工具的 "Application" 或 "Manifest" 选项卡中显示解析后的 manifest 信息，并报告解析错误。
* **参考 `manifest_parser_unittest.cc`**:  该文件中的测试用例覆盖了各种解析场景，可以帮助开发者理解 Blink 引擎是如何解析特定属性的，以及哪些情况下会产生错误。如果实际遇到的问题在单元测试中也有覆盖，那么测试用例的断言和错误信息可以提供直接的调试线索。
* **单步调试 Blink 引擎代码**:  在更复杂的情况下，开发者可能需要单步调试 Blink 引擎的源代码，例如 `blink/renderer/modules/manifest/manifest_parser.cc` 和相关的测试文件 `manifest_parser_unittest.cc`，来深入了解解析过程中的具体逻辑。

**这是第6部分，共8部分，请归纳一下它的功能:**

作为第 6 部分，这段代码主要关注 **`share_target` 属性的详细解析测试，以及 `related_applications`，`prefer_related_applications`，`theme_color` 和 `background_color` 属性的基本解析测试**。它验证了 Blink 引擎在解析这些关键的 manifest 属性时的正确性，包括对各种有效和无效的输入值的处理，以及错误信息的生成。这部分测试对于确保 Web Share API 和 PWA 的视觉体验等功能能够按照 manifest 的配置正常工作至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能

"""
manifest->share_target->params->url.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
  }

  // Return undefined if method or enctype is not string.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        10, "enctype": 10, "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "invalid method. Allowed methods are:"
        "GET and POST.",
        errors()[0]);
  }

  // Valid method and enctype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "GET", "enctype": "application/x-www-form-urlencoded",
        "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kGet);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kFormUrlEncoded);
  }

  // Auto-fill in "GET" for method and "application/x-www-form-urlencoded" for
  // enctype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kGet);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kFormUrlEncoded);
  }

  // Invalid method values, return undefined.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "", "enctype": "application/x-www-form-urlencoded", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "invalid method. Allowed methods are:"
        "GET and POST.",
        errors()[0]);
  }

  // When method is "GET", enctype cannot be anything other than
  // "application/x-www-form-urlencoded".
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "GET", "enctype": "RANDOM", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "invalid enctype. Allowed enctypes are:"
        "application/x-www-form-urlencoded and multipart/form-data.",
        errors()[0]);
  }

  // When method is "POST", enctype cannot be anything other than
  // "application/x-www-form-urlencoded" or "multipart/form-data".
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "random", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "invalid enctype. Allowed enctypes are:"
        "application/x-www-form-urlencoded and multipart/form-data.",
        errors()[0]);
  }

  // Valid enctype for when method is "POST".
  {
    auto& manifest = ParseManifestWithURLs(
        R"( { "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "application/x-www-form-urlencoded",
        "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kPost);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kFormUrlEncoded);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Valid enctype for when method is "POST".
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kPost);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Ascii in-sensitive.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "PosT", "enctype": "mUltIparT/Form-dAta", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kPost);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // No files is okay.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [] } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->method,
              mojom::blink::ManifestShareTarget::Method::kPost);
    EXPECT_EQ(manifest->share_target->enctype,
              mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Nonempty file must have POST method and multipart/form-data enctype.
  // GET method, for example, will cause an error in this case.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "GET", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["text/plain"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "invalid enctype for GET method. Only "
        "application/x-www-form-urlencoded is allowed.",
        errors()[0]);
  }

  // Nonempty file must have POST method and multipart/form-data enctype.
  // Enctype other than multipart/form-data will cause an error.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "application/x-www-form-urlencoded",
        "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["text/plain"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("files are only supported with multipart/form-data POST.",
              errors()[0]);
  }

  // Nonempty file must have POST method and multipart/form-data enctype.
  // This case is valid.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["text/plain"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_TRUE(manifest->share_target->params->files.has_value());
    EXPECT_EQ(1u, manifest->share_target->params->files->size());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Invalid mimetype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": [""]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("invalid mime type inside files.", errors()[0]);
  }

  // Invalid mimetype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["helloworld"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("invalid mime type inside files.", errors()[0]);
  }

  // Invalid mimetype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["^$/@$"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("invalid mime type inside files.", errors()[0]);
  }

  // Invalid mimetype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": ["/"]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("invalid mime type inside files.", errors()[0]);
  }

  // Invalid mimetype.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": [" "]}] } }
        })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("invalid mime type inside files.", errors()[0]);
  }

  // Accept field is empty.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "method":
        "POST", "enctype": "multipart/form-data", "params":
        { "title": "mytitle", "files": [{ "name": "name",
        "accept": []}] } }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_FALSE(manifest->share_target->params->files.has_value());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept sequence contains non-string elements.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": [{
                "name": "name",
                "accept": ["image/png", 42]
              }]
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);

    EXPECT_TRUE(share_target->params->files.has_value());
    auto& files = share_target->params->files.value();
    EXPECT_EQ(1u, files.size());
    EXPECT_EQ(files[0]->name, "name");

    auto& accept = files[0]->accept;
    EXPECT_EQ(1u, accept.size());
    EXPECT_EQ(accept[0], "image/png");

    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("'accept' entry ignored, expected to be of type string.",
              errors()[0]);
  }

  // Accept is just a single string.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": [{
                "name": "name",
                "accept": "image/png"
              }]
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);

    EXPECT_TRUE(share_target->params->files.has_value());
    auto& files = share_target->params->files.value();
    EXPECT_EQ(1u, files.size());
    EXPECT_EQ(files[0]->name, "name");

    auto& accept = files[0]->accept;
    EXPECT_EQ(1u, accept.size());
    EXPECT_EQ(accept[0], "image/png");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept is neither a string nor an array of strings.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": [{
                "name": "name",
                "accept": true
              }]
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);
    EXPECT_FALSE(share_target->params->files.has_value());

    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'accept' ignored, type array or string expected.",
              errors()[0]);
  }

  // Files is just a single FileFilter (not an array).
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": {
                "name": "name",
                "accept": "image/png"
              }
            }
          }
        })",
        manifest_url, document_url);
    EXPECT_TRUE(manifest->share_target.get());

    auto* params = manifest->share_target->params.get();
    EXPECT_TRUE(params->files.has_value());

    auto& file = params->files.value();
    EXPECT_EQ(1u, file.size());
    EXPECT_EQ(file[0]->name, "name");

    auto& accept = file[0]->accept;
    EXPECT_EQ(1u, accept.size());
    EXPECT_EQ(accept[0], "image/png");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Files is neither array nor FileFilter.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": 3
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);

    EXPECT_FALSE(share_target->params->files.has_value());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'files' ignored, type array or FileFilter expected.",
              errors()[0]);
  }

  // Files contains a non-dictionary entry.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": [
                {
                  "name": "name",
                  "accept": "image/png"
                },
                3
              ]
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);

    EXPECT_TRUE(share_target->params->files.has_value());
    auto& files = share_target->params->files.value();
    EXPECT_EQ(1u, files.size());
    EXPECT_EQ(files[0]->name, "name");

    auto& accept = files[0]->accept;
    EXPECT_EQ(1u, accept.size());
    EXPECT_EQ(accept[0], "image/png");

    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("files must be a sequence of non-empty file entries.",
              errors()[0]);
  }

  // Files contains empty file.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({
          "share_target": {
            "action": "https://foo.com/#",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
              "title": "mytitle",
              "files": [
                {
                  "name": "name",
                  "accept": "image/png"
                },
                {}
              ]
            }
          }
        })",
        manifest_url, document_url);
    auto* share_target = manifest->share_target.get();
    EXPECT_TRUE(share_target);

    EXPECT_TRUE(share_target->params->files.has_value());
    auto& files = share_target->params->files.value();
    EXPECT_EQ(1u, files.size());
    EXPECT_EQ(files[0]->name, "name");

    auto& accept = files[0]->accept;
    EXPECT_EQ(1u, accept.size());
    EXPECT_EQ(accept[0], "image/png");

    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' missing.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, RelatedApplicationsParseRules) {
  // If no application, empty list.
  {
    auto& manifest = ParseManifest(R"({ "related_applications": []})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // If empty application, empty list.
  {
    auto& manifest = ParseManifest(R"({ "related_applications": [{}]})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("'platform' is a required field, related application ignored.",
              errors()[0]);
  }

  // If invalid platform, application is ignored.
  {
    auto& manifest =
        ParseManifest(R"({ "related_applications": [{"platform": 123}]})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'platform' ignored, type string expected.",
              errors()[0]);
    EXPECT_EQ(
        "'platform' is a required field, "
        "related application ignored.",
        errors()[1]);
  }

  // If missing platform, application is ignored.
  {
    auto& manifest =
        ParseManifest(R"({ "related_applications": [{"id": "foo"}]})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("'platform' is a required field, related application ignored.",
              errors()[0]);
  }

  // If missing id and url, application is ignored.
  {
    auto& manifest =
        ParseManifest(R"({ "related_applications": [{"platform": "play"}]})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("one of 'url' or 'id' is required, related application ignored.",
              errors()[0]);
  }

  // Valid application, with url.
  {
    auto& manifest = ParseManifest(R"({ "related_applications": [
        {"platform": "play", "url": "http://www.foo.com"}]})");
    auto& related_applications = manifest->related_applications;
    EXPECT_EQ(related_applications.size(), 1u);
    EXPECT_EQ(related_applications[0]->platform, "play");
    EXPECT_TRUE(related_applications[0]->url.has_value());
    EXPECT_EQ(related_applications[0]->url->GetString(), "http://www.foo.com/");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Application with an invalid url.
  {
    auto& manifest = ParseManifest(R"({ "related_applications": [
        {"platform": "play", "url": "http://www.foo.com:co&uk"}]})");
    EXPECT_TRUE(manifest->related_applications.empty());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, URL is invalid.", errors()[0]);
    EXPECT_EQ("one of 'url' or 'id' is required, related application ignored.",
              errors()[1]);
  }

  // Valid application, with id.
  {
    auto& manifest = ParseManifest(R"({ "related_applications": [
        {"platform": "itunes", "id": "foo"}]})");
    auto& related_applications = manifest->related_applications;
    EXPECT_EQ(related_applications.size(), 1u);
    EXPECT_EQ(related_applications[0]->platform, "itunes");
    EXPECT_EQ(related_applications[0]->id, "foo");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // All valid applications are in list.
  {
    auto& manifest = ParseManifest(
        R"({ "related_applications": [
        {"platform": "play", "id": "foo"},
        {"platform": "itunes", "id": "bar"}]})");
    auto& related_applications = manifest->related_applications;
    EXPECT_EQ(related_applications.size(), 2u);
    EXPECT_EQ(related_applications[0]->platform, "play");
    EXPECT_EQ(related_applications[0]->id, "foo");
    EXPECT_EQ(related_applications[1]->platform, "itunes");
    EXPECT_EQ(related_applications[1]->id, "bar");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Two invalid applications and one valid. Only the valid application should
  // be in the list.
  {
    auto& manifest = ParseManifest(
        R"({ "related_applications": [
        {"platform": "itunes"},
        {"platform": "play", "id": "foo"},
        {}]})");
    auto& related_applications = manifest->related_applications;
    EXPECT_EQ(related_applications.size(), 1u);
    EXPECT_EQ(related_applications[0]->platform, "play");
    EXPECT_EQ(related_applications[0]->id, "foo");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("one of 'url' or 'id' is required, related application ignored.",
              errors()[0]);
    EXPECT_EQ("'platform' is a required field, related application ignored.",
              errors()[1]);
  }
}

TEST_F(ManifestParserTest, ParsePreferRelatedApplicationsParseRules) {
  // Smoke test.
  {
    auto& manifest =
        ParseManifest(R"({ "prefer_related_applications": true })");
    EXPECT_TRUE(manifest->prefer_related_applications);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if the property isn't a boolean.
  {
    auto& manifest = ParseManifest(R"({ "prefer_related_applications": {} })");
    EXPECT_FALSE(manifest->prefer_related_applications);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'prefer_related_applications' "
        "ignored, type boolean expected.",
        errors()[0]);
  }
  {
    auto& manifest =
        ParseManifest(R"({ "prefer_related_applications": "true" })");
    EXPECT_FALSE(manifest->prefer_related_applications);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'prefer_related_applications' "
        "ignored, type boolean expected.",
        errors()[0]);
  }
  {
    auto& manifest = ParseManifest(R"({ "prefer_related_applications": 1 })");
    EXPECT_FALSE(manifest->prefer_related_applications);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'prefer_related_applications' "
        "ignored, type boolean expected.",
        errors()[0]);
  }

  // "False" should set the boolean false without throwing errors.
  {
    auto& manifest =
        ParseManifest(R"({ "prefer_related_applications": false })");
    EXPECT_FALSE(manifest->prefer_related_applications);
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ThemeColorParserRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#FF0000" })");
    EXPECT_TRUE(manifest->has_theme_color);
    EXPECT_EQ(manifest->theme_color, 0xFFFF0000u);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "  blue   " })");
    EXPECT_TRUE(manifest->has_theme_color);
    EXPECT_EQ(manifest->theme_color, 0xFF0000FFu);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if theme_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": {} })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if theme_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": false })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if theme_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": null })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if theme_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": [] })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if theme_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": 42 })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, type string expected.",
              errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"~({ "theme_color": "foo(bar)" })~");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'theme_color' ignored,"
        " 'foo(bar)' is not a valid color.",
        errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "bleu" })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'theme_color' ignored, 'bleu' is not a valid color.",
              errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "FF00FF" })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'theme_color' ignored, 'FF00FF'"
        " is not a valid color.",
        errors()[0]);
  }

  // Parse fails if multiple values for theme_color are given.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#ABC #DEF" })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'theme_color' ignored, "
        "'#ABC #DEF' is not a valid color.",
        errors()[0]);
  }

  // Parse fails if multiple values for theme_color are given.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#AABBCC #DDEEFF" })");
    EXPECT_FALSE(manifest->has_theme_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'theme_color' ignored, "
        "'#AABBCC #DDEEFF' is not a valid color.",
        errors()[0]);
  }

  // Accept CSS color keyword format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "blue" })");
    EXPECT_EQ(manifest->theme_color, 0xFF0000FFu);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept CSS color keyword format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "chartreuse" })");
    EXPECT_EQ(manifest->theme_color, 0xFF7FFF00u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept CSS RGB format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#FFF" })");
    EXPECT_EQ(manifest->theme_color, 0xFFFFFFFFu);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept CSS RGB format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#ABC" })");
    EXPECT_EQ(manifest->theme_color, 0xFFAABBCCu);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept CSS RRGGBB format.
  {
    auto& manifest = ParseManifest(R"({ "theme_color": "#FF0000" })");
    EXPECT_EQ(manifest->theme_color, 0xFFFF0000u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept translucent colors.
  {
    auto& manifest =
        ParseManifest(R"~({ "theme_color": "rgba(255,0,0,0.4)" })~");
    EXPECT_EQ(manifest->theme_color, 0x66FF0000u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept transparent colors.
  {
    auto& manifest = ParseManifest(R"~({ "theme_color": "rgba(0,0,0,0)" })~");
    EXPECT_EQ(manifest->theme_color, 0x00000000u);
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, BackgroundColorParserRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "background_color": "#FF0000" })");
    EXPECT_EQ(manifest->background_color, 0xFFFF0000u);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "background_color": "  blue   " })");
    EXPECT_EQ(manifest->background_color, 0xFF0000FFu);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if background_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "background_color": {} })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'background_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if background_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "background_color": false })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'background_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if background_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "background_color": null })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'background_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if background_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "background_color": [] })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'background_color' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if background_color isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "background_color": 42 })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'background_color' ignored, type string expected.",
              errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"~({ "background_color": "foo(bar)" })~");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'background_color' ignored,"
        " 'foo(bar)' is not a valid color.",
        errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"({ "background_color": "bleu" })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'background_color' ignored,"
        " 'bleu' is not a valid color.",
        errors()[0]);
  }

  // Parse fails if string is not in a known format.
  {
    auto& manifest = ParseManifest(R"({ "background_color": "FF00FF" })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'background_color' ignored,"
        " 'FF00FF' is not a valid color.",
        errors()[0]);
  }

  // Parse fails if multiple values for background_color are given.
  {
    auto& manifest = ParseManifest(R"({ "background_color": "#ABC #DEF" })");
    EXPECT_FALSE(manifest->has_background_color);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'background_color'
"""


```