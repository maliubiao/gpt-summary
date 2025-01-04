Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of a unit test for the manifest parser in the Chromium Blink engine. The snippet focuses on testing the parsing of `file_handlers`, `protocol_handlers`, `url_handlers`, and `scope_extensions` sections within a web app manifest file.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The file `manifest_parser_unittest.cc` tests the parsing of the web app manifest. The specific sections in this snippet test how different manifest properties are parsed and validated.

2. **List the specific features being tested:** The code tests `file_handlers`, `protocol_handlers`, `url_handlers`, and `scope_extensions`.

3. **Explain the relevance to web technologies:**  These manifest features directly impact how web apps interact with the operating system and other websites.

4. **Provide examples for each feature:**  Show how these features are represented in the manifest JSON and how the parser handles valid and invalid inputs. This will involve creating hypothetical input and output scenarios.

5. **Highlight common user/developer errors:**  Based on the test cases, identify potential mistakes developers might make when defining these manifest properties.

6. **Describe the user interaction:** Explain how a user's actions (like installing a web app or clicking a link) can lead to the manifest being parsed and these features being used.

7. **Summarize the functionality of the provided part:**  Focus on the specific tests covered in this chunk of the file.

8. **Address the prompt's specific constraints:** Acknowledge that this is part 4 of 8 and tailor the summary accordingly.
这是对 `blink/renderer/modules/manifest/manifest_parser_unittest.cc` 文件中部分代码的功能归纳。这部分代码主要负责测试 Web App Manifest 文件中 `file_handlers`, `protocol_handlers`, `url_handlers`, 和 `scope_extensions` 字段的解析逻辑。

**功能归纳:**

这部分代码的功能是测试 Chromium Blink 引擎在解析 Web App Manifest 文件时，对于以下关键特性的解析是否正确：

* **`file_handlers` (文件处理器):** 测试了如何解析 `file_handlers` 数组中的每个对象，包括 `action` (处理文件的 URL), `accept` (接受的文件类型和扩展名), `launch_type` (启动类型)，以及 `icons` (文件处理器的图标)。
* **`protocol_handlers` (协议处理器):** 测试了如何解析 `protocol_handlers` 数组中的每个对象，包括 `protocol` (协议名) 和 `url` (处理该协议的 URL)。并验证了 URL 的同源性以及是否包含 `%s` 占位符。
* **`url_handlers` (URL 处理器):** 测试了如何解析 `url_handlers` 数组中的每个对象，包括 `origin` (允许处理 URL 的来源)。并验证了 `origin` 的格式（必须是 HTTPS）以及是否支持通配符。
* **`scope_extensions` (作用域扩展):** 测试了如何解析 `scope_extensions` 数组中的每个条目，可以是对象形式包含 `origin` 字段，也可以是直接的字符串形式表示 `origin`。并验证了 `origin` 的格式（必须是 HTTPS）。

**与 JavaScript, HTML, CSS 的关系:**

这些 manifest 的功能直接影响 Web 应用与操作系统和用户的交互方式，虽然不在 JavaScript, HTML, CSS 的代码中直接体现，但它们是 PWA (Progressive Web Apps) 的关键组成部分，增强了 Web 应用的功能。

* **`file_handlers`:** 允许 Web 应用注册为特定文件类型的处理器。当用户在操作系统中打开这些文件时，操作系统可以启动对应的 PWA 来处理。
    * **举例:** 用户双击一个 `.csv` 文件，如果一个 PWA 注册了处理 `text/csv` 类型的文件，并且 `action` 指向了 `/files` 路径，那么浏览器可能会启动该 PWA，并导航到其 `/files` 页面，并将该 `.csv` 文件的信息传递给 PWA。这需要 JavaScript 代码在 `/files` 页面接收并处理文件数据。
* **`protocol_handlers`:** 允许 Web 应用注册为特定 URL 协议的处理器。当用户点击一个特定的链接时，操作系统可以启动对应的 PWA 来处理。
    * **举例:**  一个网站包含链接 `<a href="web+image:view?url=https://example.com/image.png">View Image</a>`。如果一个 PWA 注册了 `web+image` 协议，并且 `url` 设置为 `/?action=view&url=%s`，那么点击这个链接将会启动该 PWA 并导航到 `/?action=view&url=https://example.com/image.png`。JavaScript 代码需要解析 URL 参数并执行相应的操作（比如显示图片）。
* **`url_handlers`:** 允许一个 Web 应用声明它可以处理来自特定来源的链接，即使这些链接不是该应用自身的链接。
    * **举例:**  一个 PWA 的 manifest 中声明了 `url_handlers` 包含 `https://example.com`。当用户点击来自 `https://example.com` 的一个链接，即使这个链接指向的是该 PWA 自身域名的其他页面，浏览器也会优先在该 PWA 的上下文中打开这个链接。这影响了浏览器的导航行为，无需 JavaScript 或 CSS 直接参与，但影响了 Web 应用的整体体验。
* **`scope_extensions`:**  允许 Web 应用扩展其作用域到其他来源。这影响了浏览器如何判断一个 URL 是否在 Web 应用的范围内，从而影响诸如 Service Worker 的注册和权限等。
    * **举例:**  一个 PWA 在其 manifest 中声明了 `scope_extensions` 包含 `https://another-domain.com`。那么来自 `https://another-domain.com` 的页面也会被视为该 PWA 的作用域内，这意味着该 PWA 的 Service Worker 可以拦截和处理来自该域名的请求。这主要影响浏览器行为，而不是直接的 JavaScript, HTML 或 CSS 代码。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `file_handlers` 的 `launch_type` 测试):**

```json
{
  "file_handlers": [
    {
      "action": "/files",
      "accept": {
        "image/png": ".png"
      },
      "launch_type": "multiple-clients"
    },
    {
      "action": "/files2",
      "accept": {
        "image/jpeg": ".jpeg"
      }
    }
  ]
}
```

**假设输出 (对应的 C++ 测试断言结果):**

```c++
EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kMultipleClients,
          manifest->file_handlers[0]->launch_type);
EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kSingleClient,
          manifest->file_handlers[1]->launch_type);
```

**假设输入 (针对 `protocol_handlers` 的有效解析):**

```json
{
  "protocol_handlers": [
    {
      "protocol": "web+mail",
      "url": "/compose?to=%s"
    }
  ]
}
```

**假设输出 (对应的 C++ 测试断言结果):**

```c++
ASSERT_EQ("web+mail", protocol_handlers[0]->protocol);
ASSERT_EQ("http://foo.com/compose?to=%s", protocol_handlers[0]->url); // 假设 manifest 的作用域是 http://foo.com
```

**用户或编程常见的使用错误举例:**

* **`file_handlers` 中 `accept` 字段的格式错误:**
    ```json
    {
      "file_handlers": [
        {
          "accept": "image/png" // 错误: 应该是一个对象
        }
      ]
    }
    ```
    **错误说明:** 用户可能错误地将 `accept` 字段写成字符串，而它应该是一个对象，键是 MIME 类型，值是文件扩展名数组或字符串。
* **`protocol_handlers` 中 `url` 没有包含 `%s`:**
    ```json
    {
      "protocol_handlers": [
        {
          "protocol": "web+test",
          "url": "/test" // 错误: 缺少参数占位符
        }
      ]
    }
    ```
    **错误说明:**  开发者忘记在 `url` 中包含 `%s` 占位符来接收传递的参数。
* **`url_handlers` 中 `origin` 使用非 HTTPS 协议:**
    ```json
    {
      "url_handlers": [
        {
          "origin": "http://example.com" // 错误: 必须是 HTTPS
        }
      ]
    }
    ```
    **错误说明:** 用户可能不了解 `url_handlers` 的安全要求，错误地使用了 HTTP 协议。
* **`scope_extensions` 中 `origin` 使用非 HTTPS 协议:**
    ```json
    {
      "scope_extensions": [
        "http://example.com" // 错误: 必须是 HTTPS
      ]
    }
    ```
    **错误说明:** 用户可能不了解 `scope_extensions` 的安全要求，错误地使用了 HTTP 协议。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **开发者创建或修改 Web App Manifest 文件:** 开发者在其 Web 应用的根目录下创建一个 `manifest.json` 文件，或者修改已有的文件，其中包含了 `file_handlers`, `protocol_handlers`, `url_handlers`, 或 `scope_extensions` 字段。
2. **浏览器请求 Manifest 文件:** 当用户首次访问该 Web 应用时，或者当浏览器检测到 manifest 文件更新时，浏览器会向服务器请求 `manifest.json` 文件。通常是通过 HTML 中的 `<link rel="manifest" href="manifest.json">` 标签声明。
3. **Blink 引擎解析 Manifest 文件:** 浏览器下载到 manifest 文件后，Blink 渲染引擎会负责解析这个 JSON 文件。
4. **`ManifestParser` 类的使用:**  Blink 引擎内部的 `ManifestParser` 类会读取 manifest 文件的内容，并根据定义的规则解析各个字段。
5. **执行单元测试:**  在 Chromium 开发过程中，为了确保 `ManifestParser` 的解析逻辑正确，开发者会编写单元测试，比如 `manifest_parser_unittest.cc` 中的测试用例。这些测试用例模拟各种合法的和非法的 manifest 文件内容，以验证解析器的行为是否符合预期。当代码被修改后，会重新运行这些测试，以确保没有引入新的错误。
6. **测试失败时的调试:** 如果单元测试失败，开发者会查看失败的测试用例，检查输入的 manifest 内容和期望的输出结果，从而定位解析器中的 bug。这部分代码就是用来验证特定字段解析逻辑的正确性。

**这是第4部分，共8部分，请归纳一下它的功能:**

考虑到这是第 4 部分，并且之前的测试用例可能涵盖了 Manifest 文件的基本结构和更简单的字段，这部分代码主要专注于测试 **Web App Manifest 中与操作系统和外部内容交互的高级特性** 的解析，包括文件处理、协议处理、跨域 URL 处理和作用域扩展。它验证了 Blink 引擎对于这些复杂且重要的 PWA 功能的解析逻辑的正确性和健壮性。

Prompt: 
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能

"""
]->name);
    EXPECT_EQ(1u, file_handlers[0]->accept.find("text/csv")->value.size());

    EXPECT_EQ("Graph", file_handlers[1]->name);
    auto accept_map = file_handlers[1]->accept.find("text/svg+xml")->value;
    ASSERT_EQ(4u, accept_map.size());
    EXPECT_TRUE(accept_map.Contains(".graph1"));
    EXPECT_TRUE(accept_map.Contains(".graph2"));
    EXPECT_TRUE(accept_map.Contains(".graph3"));
    EXPECT_TRUE(accept_map.Contains(".graph4"));
  }

  // Test `launch_type` parsing and default.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "action": "/files",
              "accept": {
                "image/png": ".png"
              },
              "launch_type": "multiple-clients"
            },
            {
              "action": "/files2",
              "accept": {
                "image/jpeg": ".jpeg"
              },
              "launch_type": "single-client"
            },
            {
              "action": "/files3",
              "accept": {
                "text/plain": ".txt"
              }
            },
            {
              "action": "/files4",
              "accept": {
                "text/csv": ".csv"
              },
              "launch_type": "multiple-client"
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    ASSERT_EQ(4U, manifest->file_handlers.size());
    EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kMultipleClients,
              manifest->file_handlers[0]->launch_type);
    EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kSingleClient,
              manifest->file_handlers[1]->launch_type);
    EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kSingleClient,
              manifest->file_handlers[2]->launch_type);
    // This one has a typo.
    EXPECT_EQ(mojom::blink::ManifestFileHandler::LaunchType::kSingleClient,
              manifest->file_handlers[3]->launch_type);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("launch_type value 'multiple-client' ignored, unknown value.",
              errors()[0]);
  }
}

TEST_F(ManifestParserTest, FileHandlerIconsParseRules) {
  // Smoke test: if no icons, file_handler->icon has no value.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_TRUE(manifest->file_handlers[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if empty icon, file_handler->icons has no value.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{}],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_TRUE(manifest->file_handlers[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: icon with invalid src, file_handler->icons has no value.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{ "icons": [] }],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_TRUE(manifest->file_handlers[0]->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if icon with empty src, it will be present in
  // file_handler->icons.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{ "src": "" }],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_FALSE(manifest->file_handlers[0]->icons.empty());

    auto& icons = manifest->file_handlers[0]->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/manifest.json");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if one icon with valid src, it will be present in
  // file_handler->icons.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{ "src": "foo.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_FALSE(manifest->file_handlers[0]->icons.empty());
    auto& icons = manifest->file_handlers[0]->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if >1 icon with valid src, it will be present in
  // file_handler->icons.
  {
    auto& manifest = ParseManifest(
        R"({
          "file_handlers": [
            {
              "icons": [{ "src": "foo.jpg" }, { "src": "bar.jpg" }],
              "action": "/files",
              "accept": {
                "image/png": ".png"
              }
            }
          ]
        })");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(manifest->file_handlers.empty());
    EXPECT_FALSE(manifest->file_handlers[0]->icons.empty());
    auto& icons = manifest->file_handlers[0]->icons;
    EXPECT_EQ(icons.size(), 2u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_EQ(icons[1]->src.GetString(), "http://foo.com/bar.jpg");
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ProtocolHandlerParseRules) {
  // Does not contain protocol_handlers field.
  {
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->protocol_handlers.size());
  }

  // protocol_handlers is not an array.
  {
    auto& manifest = ParseManifest(R"({ "protocol_handlers": { } })");
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'protocol_handlers' ignored, type array expected.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->protocol_handlers.size());
  }

  // Contains protocol_handlers field but no protocol handlers.
  {
    auto& manifest = ParseManifest(R"({ "protocol_handlers": [ ] })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->protocol_handlers.size());
  }

  // Entries must be objects
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            "hello world"
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("protocol_handlers entry ignored, type object expected.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->protocol_handlers.size());
  }

  // A valid protocol handler.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "protocol": "web+github",
              "url": "http://foo.com/?profile=%s"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, protocol_handlers.size());

    ASSERT_EQ("web+github", protocol_handlers[0]->protocol);
    ASSERT_EQ("http://foo.com/?profile=%s", protocol_handlers[0]->url);
  }

  // An invalid protocol handler with the URL not being from the same origin.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "protocol": "web+github",
              "url": "http://bar.com/?profile=%s"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, should be within scope of the manifest.",
              errors()[0]);
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'url' is invalid.",
        errors()[1]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // An invalid protocol handler with the URL not being within manifest scope.
  {
    auto& manifest = ParseManifest(
        R"({
          "start_url": "/app/",
          "scope": "/app/",
          "protocol_handlers": [
            {
              "protocol": "web+github",
              "url": "/?profile=%s"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'url' ignored, should be within scope of the manifest.",
              errors()[0]);
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'url' is invalid.",
        errors()[1]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // An invalid protocol handler with no value for protocol.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "url": "http://foo.com/?profile=%s"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'protocol' is "
        "missing.",
        errors()[0]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // An invalid protocol handler with no url.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "protocol": "web+github"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'url' is missing.",
        errors()[0]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // An invalid protocol handler with a url that doesn't contain the %s token.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "protocol": "web+github",
              "url": "http://foo.com/?profile="
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "The url provided ('http://foo.com/?profile=') does not contain '%s'.",
        errors()[0]);
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'url' is invalid.",
        errors()[1]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // An invalid protocol handler with a non-allowed protocol.
  {
    auto& manifest = ParseManifest(R"({
          "protocol_handlers": [
            {
              "protocol": "github",
              "url": "http://foo.com/?profile="
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "The scheme 'github' doesn't belong to the scheme allowlist. Please "
        "prefix non-allowlisted schemes with the string 'web+'.",
        errors()[0]);
    EXPECT_EQ(
        "protocol_handlers entry ignored, required property 'protocol' is "
        "invalid.",
        errors()[1]);
    ASSERT_EQ(0u, protocol_handlers.size());
  }

  // Multiple valid protocol handlers
  {
    auto& manifest = ParseManifest(
        R"({
          "protocol_handlers": [
            {
              "protocol": "web+github",
              "url": "http://foo.com/?profile=%s"
            },
            {
              "protocol": "web+test",
              "url": "http://foo.com/?test=%s"
            },
            {
              "protocol": "web+relative",
              "url": "relativeURL=%s"
            }
          ]
        })");
    auto& protocol_handlers = manifest->protocol_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(3u, protocol_handlers.size());

    ASSERT_EQ("web+github", protocol_handlers[0]->protocol);
    ASSERT_EQ("http://foo.com/?profile=%s", protocol_handlers[0]->url);
    ASSERT_EQ("web+test", protocol_handlers[1]->protocol);
    ASSERT_EQ("http://foo.com/?test=%s", protocol_handlers[1]->url);
    ASSERT_EQ("web+relative", protocol_handlers[2]->protocol);
    ASSERT_EQ("http://foo.com/relativeURL=%s", protocol_handlers[2]->url);
  }
}

TEST_F(ManifestParserTest, UrlHandlerParseRules) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(blink::features::kWebAppEnableUrlHandlers);

  // Manifest does not contain a 'url_handlers' field.
  {
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->url_handlers.size());
  }

  // 'url_handlers' is not an array.
  {
    auto& manifest = ParseManifest(R"({ "url_handlers": { } })");
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'url_handlers' ignored, type array expected.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->url_handlers.size());
  }

  // Contains 'url_handlers' field but no URL handler entries.
  {
    auto& manifest = ParseManifest(R"({ "url_handlers": [ ] })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->url_handlers.size());
  }

  // 'url_handlers' array entries must be objects.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            "foo.com"
          ]
        })");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("url_handlers entry ignored, type object expected.", errors()[0]);
    EXPECT_EQ(0u, manifest->url_handlers.size());
  }

  // A valid url handler.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://foo.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
  }

  // Scheme must be https.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "http://foo.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "url_handlers entry ignored, required property 'origin' must use the "
        "https scheme.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Origin must be valid.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https:///////"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "url_handlers entry ignored, required property 'origin' is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse multiple valid handlers.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://foo.com"
            },
            {
              "origin": "https://bar.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(2u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://bar.com")
                    ->IsSameOriginWith(url_handlers[1]->origin.get()));
  }

  // Parse both valid and invalid handlers.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://foo.com"
            },
            {
              "origin": "about:"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "url_handlers entry ignored, required property 'origin' is invalid.",
        errors()[0]);
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
  }

  // Parse invalid handler where the origin is a TLD.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://co.uk"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse origin with wildcard.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*.foo.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
    ASSERT_TRUE(url_handlers[0]->has_origin_wildcard);
  }

  // Parse invalid origin wildcard format.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*foo.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://*foo.com")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
    ASSERT_FALSE(url_handlers[0]->has_origin_wildcard);
  }

  // Parse origin where the host is just the wildcard prefix.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*."
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse invalid origin where wildcard is used with a TLD.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*.com"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse invalid origin where wildcard is used with an unknown TLD.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*.foo"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse invalid origin where wildcard is used with a multipart TLD.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*.co.uk"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, url_handlers.size());
  }

  // Parse valid origin with private registry.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://*.glitch.me"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://glitch.me")
                    ->IsSameOriginWith(url_handlers[0]->origin.get()));
    ASSERT_TRUE(url_handlers[0]->has_origin_wildcard);
  }

  // Parse valid IP address as origin.
  {
    auto& manifest = ParseManifest(R"({
          "url_handlers": [
            {
              "origin": "https://192.168.0.1:8888"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, url_handlers.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8888")
            ->IsSameOriginWith(url_handlers[0]->origin.get()));
    ASSERT_FALSE(url_handlers[0]->has_origin_wildcard);
  }

  // Validate only the first 10 handlers are parsed. The following manifest
  // specifies 11 handlers, so the last one should not be in the result.
  {
    auto& manifest = ParseManifest(
        R"({
          "url_handlers": [
            {
              "origin": "https://192.168.0.1:8001"
            },
            {
              "origin": "https://192.168.0.1:8002"
            },
            {
              "origin": "https://192.168.0.1:8003"
            },
            {
              "origin": "https://192.168.0.1:8004"
            },
            {
              "origin": "https://192.168.0.1:8005"
            },
            {
              "origin": "https://192.168.0.1:8006"
            },
            {
              "origin": "https://192.168.0.1:8007"
            },
            {
              "origin": "https://192.168.0.1:8008"
            },
            {
              "origin": "https://192.168.0.1:8009"
            },
            {
              "origin": "https://192.168.0.1:8010"
            },
            {
              "origin": "https://192.168.0.1:8011"
            }
          ]
        })");
    auto& url_handlers = manifest->url_handlers;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'url_handlers' contains more than 10 valid elements, "
        "only the first 10 are parsed.",
        errors()[0]);
    ASSERT_EQ(10u, url_handlers.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8010")
            ->IsSameOriginWith(url_handlers[9]->origin.get()));
  }
}

TEST_F(ManifestParserTest, ScopeExtensionParseRules) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      blink::features::kWebAppEnableScopeExtensions);

  // Manifest does not contain a 'scope_extensions' field.
  {
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->scope_extensions.size());
  }

  // 'scope_extensions' is not an array.
  {
    auto& manifest = ParseManifest(R"({ "scope_extensions": { } })");
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'scope_extensions' ignored, type array expected.",
              errors()[0]);
    EXPECT_EQ(0u, manifest->scope_extensions.size());
  }

  // Contains 'scope_extensions' field but no scope extension entries.
  {
    auto& manifest = ParseManifest(R"({ "scope_extensions": [ ] })");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_EQ(0u, manifest->scope_extensions.size());
  }

  // Scope extension entry must be an object or a string.
  {
    auto& manifest = ParseManifest(R"({ "scope_extensions": [ 7 ] })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("scope_extensions entry ignored, type string or object expected.",
              errors()[0]);
    EXPECT_EQ(0u, scope_extensions.size());
  }

  // A valid scope extension.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://foo.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // A valid scope extension in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://foo.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // Origin field is missing from the scope extension entry.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "invalid_field": "https://foo.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' is "
        "missing.",
        errors()[0]);
    EXPECT_EQ(0u, scope_extensions.size());
  }

  // Scope extension entry origin must be a string.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": 7
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'origin' ignored, type string expected.", errors()[0]);
    EXPECT_EQ(0u, scope_extensions.size());
  }

  // Scheme must be https.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "http://foo.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' must use "
        "the https scheme.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Scheme must be https in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "http://foo.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' must use "
        "the https scheme.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Origin must be valid.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https:///////"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Origin must be valid in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https:///////"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse multiple valid scope extensions.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://foo.com"
            },
            {
              "origin": "https://bar.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(2u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://bar.com")
                    ->IsSameOriginWith(scope_extensions[1]->origin.get()));
  }

  // Parse multiple valid scope extensions in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://foo.com",
            "https://bar.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(2u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://bar.com")
                    ->IsSameOriginWith(scope_extensions[1]->origin.get()));
  }

  // Parse invalid scope extensions list with an array entry.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://foo.com"
            },
            []
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("scope_extensions entry ignored, type string or object expected.",
              errors()[0]);
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // Parse invalid scope extensions list with an array entry in shorthand
  // format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://foo.com",
            []
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("scope_extensions entry ignored, type string or object expected.",
              errors()[0]);
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // Parse invalid scope extensions list with entries in mixed formats.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://foo.com"
            },
            "https://bar.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("scope_extensions entry ignored, type object expected.",
              errors()[0]);
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // Parse both valid and invalid scope extensions.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://foo.com"
            },
            {
              "origin": "about:"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
  }

  // Parse both valid and invalid scope extensions in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://foo.com",
            "about:"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, required property 'origin' is "
        "invalid.",
        errors()[0]);
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.g
"""


```