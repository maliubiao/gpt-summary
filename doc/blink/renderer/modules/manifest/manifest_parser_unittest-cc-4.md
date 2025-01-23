Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for parsing web manifest files in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Function:** The file name `manifest_parser_unittest.cc` immediately suggests that this code is testing the parsing of web manifest files. The presence of `TEST_F` macros confirms this is a unit test.

2. **Analyze the Test Cases:** Each `TEST_F` function focuses on a specific aspect of manifest parsing. Scan through the names of the test functions and the descriptions within them (the comments and the JSON snippets).

3. **Categorize the Functionality:** Group the test cases by the manifest properties they are testing. In this snippet, the main focus is on `scope_extensions`, `lock_screen`, `note_taking`, and `share_target`.

4. **Examine the Test Logic:**  For each test case, observe the following:
    * **Input:** The JSON string representing a manifest snippet.
    * **Parsing:** The `ParseManifest` or `ParseManifestWithURLs` functions are used to parse the input.
    * **Assertions:** `ASSERT_EQ`, `EXPECT_EQ`, and `ASSERT_TRUE`/`ASSERT_FALSE` are used to check the parsed results and the number of errors. Pay close attention to what properties are being checked and what the expected values are.

5. **Relate to Web Technologies:** Consider how the tested manifest properties relate to HTML, CSS, and JavaScript.
    * `scope_extensions`:  Deals with the scope of a web application, potentially influencing how JavaScript interacts with different origins.
    * `lock_screen`:  Relates to displaying information on the device's lock screen, a feature often driven by JavaScript.
    * `note_taking`:  Facilitates integration with note-taking applications, likely triggered by user interactions and JavaScript calls.
    * `share_target`: Enables sharing content to the web app, initiated from other applications or the browser, and handled by JavaScript.

6. **Identify Logic and Assumptions:**  Look for patterns in the tests, like testing valid and invalid inputs. Notice the assumptions made by the parser, such as the maximum number of scope extensions allowed. Infer potential input and output examples based on the test cases.

7. **Identify Potential User Errors:**  Based on the error messages in the tests, determine common mistakes developers might make when creating manifest files (e.g., invalid URLs, incorrect data types, using wildcards improperly).

8. **Infer User Actions:** Think about how a user's interaction with a website or web app might lead to the manifest being parsed (e.g., visiting a site, adding it to the home screen, sharing content).

9. **Synthesize the Summary:** Combine the observations into a concise description of the file's purpose and the specific functionalities it tests. Address each of the user's request points (functionality, relationship to web technologies, logic/assumptions, user errors, user actions).

10. **Consider the "Part X of Y" Context:**  Since this is part 5 of 8, understand that this file likely focuses on a subset of the overall manifest parsing functionality. The summary should reflect this limited scope.

By following these steps, we can create a comprehensive and accurate summary of the provided code snippet, addressing all aspects of the user's request.
这是文件 `blink/renderer/modules/manifest/manifest_parser_unittest.cc` 的第 5 部分，它专门测试 Blink 引擎中 manifest 文件解析器的功能。根据提供的代码片段，本部分主要关注以下 manifest 属性的解析规则和正确性：

**主要功能点:**

1. **`scope_extensions` 属性解析:**
   - **功能:**  测试对 `scope_extensions` 属性的解析，该属性允许 Web 应用声明额外的作用域，超出其默认的 manifest 文件所在目录。这可以用来控制 Web 应用能访问哪些 origin 的资源。
   - **测试用例:**
     - 解析有效的 `scope_extensions` 条目，包括对象格式和简写格式。
     - 解析无效的 `scope_extensions` 条目，例如缺少 `origin` 属性、`origin` 不是有效 URL、`origin` 是顶级域名 (TLD)、`origin` 中通配符使用不当等。
     - 测试通配符 `*` 在 `origin` 中的使用规则，包括有效的和无效的情况，以及对私有注册域名和 IP 地址的支持。
     - 验证只解析前 10 个有效的 `scope_extensions` 条目，超出限制的条目将被忽略并产生错误。

2. **`lock_screen` 属性解析:**
   - **功能:** 测试对 `lock_screen` 属性的解析，该属性允许 Web 应用自定义在设备锁屏上显示的内容，通常包含一个 `start_url`。
   - **测试用例:**
     - 解析不存在 `lock_screen` 属性的情况。
     - 解析 `lock_screen` 属性值不是对象的情况。
     - 解析 `lock_screen` 对象但缺少 `start_url` 属性的情况。
     - 解析 `start_url` 不是有效 URL 或不在 manifest 作用域内的情况。
     - 解析有效的 `lock_screen` 和 `start_url`，包括绝对 URL 和相对于 manifest 文件 URL 的相对 URL。

3. **`note_taking` 属性解析:**
   - **功能:** 测试对 `note_taking` 属性的解析，该属性允许 Web 应用声明用于创建新笔记的 URL (通常是 `new_note_url`)。
   - **测试用例:**
     - 解析不存在 `note_taking` 属性的情况。
     - 解析 `note_taking` 属性值不是对象的情况。
     - 解析 `note_taking` 对象但缺少 `new_note_url` 属性的情况。
     - 解析 `new_note_url` 不是有效 URL 或不在 manifest 作用域内的情况。
     - 解析有效的 `note_taking` 和 `new_note_url`，包括绝对 URL 和相对于 manifest 文件 URL 的相对 URL。

4. **`share_target` 属性解析:**
   - **功能:** 测试对 `share_target` 属性的解析，该属性定义了 Web 应用如何接收来自其他应用的共享数据。
   - **测试用例:**
     - 解析 `share_target` 对象但缺少必要的键 (例如 `action` 或 `params`) 的情况。
     - 解析 `share_target` 对象包含无效键的情况。

5. **`share_target` 及其子属性 (如 `action`, `params`) 的详细解析规则:**
   - **功能:**  深入测试 `share_target` 属性中 `action` 和 `params` 等子属性的解析，包括 URL 的有效性、数据类型的正确性、作用域限制等。
   - **测试用例:**
     - 解析 `action` 为空字符串的情况。
     - 解析 `action` 或 `params` 属性值类型不正确的情况。
     - 解析 `params` 中子属性 (如 `text`, `title`, `url`) 类型不正确的情况。
     - 解析 `action` 不是有效 URL 的情况。
     - 解析 `action` 不在 manifest 文件作用域内的情况。
     - 解析 `action` 为相对 URL 和绝对 URL 的情况。
     - 解析包含 `url_template` 属性（用于向后兼容）的情况。
     - 测试 `share_target` 中 `params` 属性不同子键都存在的情况。

**与 JavaScript, HTML, CSS 的关系:**

- **`scope_extensions`:**  虽然 manifest 本身是 JSON 文件，但 `scope_extensions` 定义的作用域会影响浏览器如何处理 JavaScript 的 Same-Origin Policy。例如，如果一个页面通过 `scope_extensions` 获得了访问另一个 origin 的权限，那么其 JavaScript 代码可能可以访问该 origin 的资源，否则会被阻止。
    - **假设输入:**  一个 manifest 文件包含  `"scope_extensions": ["https://example.com"]`。
    - **输出:**  解析器成功解析 `scope_extensions` 属性，并将其存储为一个包含 `https://example.com` origin 的列表。
- **`lock_screen`:**  `lock_screen` 属性中的 `start_url` 指向的页面可能包含 HTML、CSS 和 JavaScript 代码，用于在锁屏上呈现特定的用户界面。
    - **假设输入:**  一个 manifest 文件包含 `"lock_screen": { "start_url": "/lockscreen.html" }`，且 manifest 文件位于 `https://app.example.com/manifest.json`。
    - **输出:** 解析器将 `start_url` 解析为 `https://app.example.com/lockscreen.html`。
- **`note_taking`:**  `note_taking` 属性中的 `new_note_url` 指向的页面很可能包含 HTML 表单和 JavaScript 代码，用于创建新的笔记。
    - **假设输入:**  一个 manifest 文件包含 `"note_taking": { "new_note_url": "/newnote" }`，且 manifest 文件位于 `https://notes.example.com/manifest.json`。
    - **输出:** 解析器将 `new_note_url` 解析为 `https://notes.example.com/newnote`。
- **`share_target`:**  `share_target` 属性定义了当用户从其他应用分享内容到该 Web 应用时，浏览器如何构造请求。`action` 指向的 URL 通常会处理一个 HTML 表单，并可能使用 JavaScript 来进一步处理接收到的数据。`params` 定义了表单中字段的名称。
    - **假设输入:**  一个 manifest 文件包含 `"share_target": { "action": "/share", "params": { "text": "shared_text", "url": "shared_url" } }`。
    - **输出:** 解析器会将 `action` 解析为相对于 manifest 文件 URL 的完整 URL，并记录 `params` 中定义的字段名称。当其他应用分享文本和 URL 到该 Web 应用时，浏览器会向 `/share` 发送一个包含 `shared_text` 和 `shared_url` 字段的请求。

**逻辑推理的假设输入与输出:**

在测试 `scope_extensions` 通配符时：
- **假设输入:**  `"scope_extensions": [ { "origin": "https://*.example.com" } ]`
- **输出:**  解析成功，`scope_extensions` 列表中包含一个 origin 为 `https://example.com` 且 `has_origin_wildcard` 为 true 的条目。

在测试 `lock_screen` 的 `start_url` 作用域时：
- **假设输入:** manifest URL 为 `https://app.example.com/manifest.json`，内容为 `"lock_screen": { "start_url": "https://other.example.com/lock" }`。
- **输出:** 解析失败，产生错误信息 "property 'start_url' ignored, should be within scope of the manifest."，`lock_screen` 的 `start_url` 为空。

**用户或编程常见的使用错误举例:**

- **忘记在 `scope_extensions` 中指定 `origin` 属性。** 这会导致解析错误，因为 `origin` 是必需的。
- **在 `scope_extensions` 的 `origin` 中错误地使用通配符，例如 `https://*foo.com` 或 `https://*.com`。** 这会导致解析错误或通配符被错误地解释。
- **在 `lock_screen` 或 `note_taking` 中提供超出 manifest 作用域的 `start_url` 或 `new_note_url`。** 这会导致这些 URL 被忽略。
- **在 `share_target` 中 `action`  指向不同的 origin 或超出 manifest 作用域的路径。** 这会导致 `share_target` 属性被忽略。
- **在 `share_target` 的 `params` 中使用错误的数据类型。** 例如，将 `text` 的值设置为数字而不是字符串。

**用户操作到达这里的调试线索:**

1. **开发者创建了一个 Web 应用并编写了一个 manifest 文件。**
2. **该 manifest 文件包含了 `scope_extensions`、`lock_screen`、`note_taking` 或 `share_target` 属性。**
3. **开发者在浏览器中加载该 Web 应用，或者将该 Web 应用添加到桌面或启动屏幕。**
4. **Blink 引擎会尝试下载和解析该 manifest 文件。**
5. **如果 manifest 文件中与 `scope_extensions`、`lock_screen`、`note_taking` 或 `share_target` 相关的部分存在语法错误或逻辑错误，`manifest_parser_unittest.cc` 中相应的测试用例就会失败。**
6. **开发者在调试 Chromium 源码时，可能会运行这些单元测试来验证 manifest 解析器的正确性，或者在遇到与 manifest 文件处理相关的问题时，查看这些测试用例以了解预期的行为和可能的错误原因。**
7. **更具体地，如果用户在使用 Web 应用的锁屏功能、笔记功能或分享功能时遇到问题，开发者可能会检查 manifest 文件中 `lock_screen`、`note_taking` 或 `share_target` 属性的配置是否正确，并参考这些单元测试来排查解析问题。**

**本部分功能归纳:**

这是 `manifest_parser_unittest.cc` 文件的第五部分，专门测试了 Blink 引擎 manifest 解析器对 `scope_extensions`、`lock_screen`、`note_taking` 和 `share_target` 这四个关键 manifest 属性的解析逻辑。它涵盖了各种有效和无效的配置场景，包括数据类型、URL 格式、作用域限制以及通配符的使用规则，旨在确保 manifest 文件中这些属性能够被正确解析和处理，从而保证 Web 应用相关功能的正常运行。

### 提示词
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
et()));
  }

  // Parse invalid scope extension where the origin is a TLD.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://co.uk"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid scope extension where the origin is a TLD in shorthand
  // format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://co.uk"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse origin with wildcard.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*.foo.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse origin with wildcard in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*.foo.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse invalid origin wildcard format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*foo.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://*foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_FALSE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse invalid origin wildcard format in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*foo.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://*foo.com")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_FALSE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse origin where the host is just the wildcard prefix.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*."
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse origin where the host is just the wildcard prefix in shorthand
  // format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*."
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with a TLD.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*.com"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with a TLD in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*.com"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with an unknown TLD.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*.foo"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with an unknown TLD in
  // shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*.foo"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with a multipart TLD.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*.co.uk"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse invalid origin where wildcard is used with a multipart TLD in
  // shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*.co.uk"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    ASSERT_EQ(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.",
        errors()[0]);
    ASSERT_EQ(0u, scope_extensions.size());
  }

  // Parse valid origin with private registry.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://*.glitch.me"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://glitch.me")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse valid origin with private registry in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://*.glitch.me"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(blink::SecurityOrigin::CreateFromString("https://glitch.me")
                    ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_TRUE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse valid IP address as origin.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            {
              "origin": "https://192.168.0.1:8888"
            }
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8888")
            ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_FALSE(scope_extensions[0]->has_origin_wildcard);
  }

  // Parse valid IP address as origin in shorthand format.
  {
    auto& manifest = ParseManifest(R"({
          "scope_extensions": [
            "https://192.168.0.1:8888"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_EQ(1u, scope_extensions.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8888")
            ->IsSameOriginWith(scope_extensions[0]->origin.get()));
    ASSERT_FALSE(scope_extensions[0]->has_origin_wildcard);
  }

  // Validate only the first 10 scope extensions are parsed. The following
  // manifest specifies 11 scope extensions, so the last one should not be in
  // the result.
  {
    auto& manifest = ParseManifest(
        R"({
          "scope_extensions": [
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
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'scope_extensions' contains more than 10 valid elements, "
        "only the first 10 are parsed.",
        errors()[0]);
    ASSERT_EQ(10u, scope_extensions.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8010")
            ->IsSameOriginWith(scope_extensions[9]->origin.get()));
  }

  // Validate only the first 10 scope extensions are parsed in shorthand format.
  // The following manifest specifies 11 scope extensions, so the last one
  // should not be in the result.
  {
    auto& manifest = ParseManifest(
        R"({
          "scope_extensions": [
            "https://192.168.0.1:8001",
            "https://192.168.0.1:8002",
            "https://192.168.0.1:8003",
            "https://192.168.0.1:8004",
            "https://192.168.0.1:8005",
            "https://192.168.0.1:8006",
            "https://192.168.0.1:8007",
            "https://192.168.0.1:8008",
            "https://192.168.0.1:8009",
            "https://192.168.0.1:8010",
            "https://192.168.0.1:8011"
          ]
        })");
    auto& scope_extensions = manifest->scope_extensions;

    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'scope_extensions' contains more than 10 valid elements, "
        "only the first 10 are parsed.",
        errors()[0]);
    ASSERT_EQ(10u, scope_extensions.size());
    ASSERT_TRUE(
        blink::SecurityOrigin::CreateFromString("https://192.168.0.1:8010")
            ->IsSameOriginWith(scope_extensions[9]->origin.get()));
  }
}

TEST_F(ManifestParserTest, LockScreenParseRules) {
  KURL manifest_url = KURL("https://foo.com/manifest.json");
  KURL document_url = KURL("https://foo.com/index.html");

  {
    // Manifest does not contain a 'lock_screen' field.
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_TRUE(manifest->lock_screen.is_null());
  }

  {
    // 'lock_screen' is not an object.
    auto& manifest = ParseManifest(R"( { "lock_screen": [ ] } )");
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'lock_screen' ignored, type object expected.",
              errors()[0]);
    EXPECT_TRUE(manifest->lock_screen.is_null());
  }

  {
    // Contains 'lock_screen' field but no start_url entry.
    auto& manifest = ParseManifest(R"( { "lock_screen": { } } )");
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->lock_screen.is_null());
    EXPECT_TRUE(manifest->lock_screen->start_url.IsEmpty());
  }

  {
    // 'start_url' entries must be valid URLs.
    auto& manifest =
        ParseManifest(R"({ "lock_screen": { "start_url": {} } } )");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'start_url' ignored, type string expected.",
              errors()[0]);
    ASSERT_FALSE(manifest->lock_screen.is_null());
    EXPECT_TRUE(manifest->lock_screen->start_url.IsEmpty());
  }

  {
    // 'start_url' entries must be within scope.
    auto& manifest = ParseManifest(
        R"({ "lock_screen": { "start_url": "https://bar.com" } } )");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'start_url' ignored, should be within scope of the manifest.",
        errors()[0]);
    ASSERT_FALSE(manifest->lock_screen.is_null());
    EXPECT_TRUE(manifest->lock_screen->start_url.IsEmpty());
  }

  {
    // A valid lock_screen start_url entry.
    auto& manifest = ParseManifestWithURLs(
        R"({
          "lock_screen": {
            "start_url": "https://foo.com"
          }
        })",
        manifest_url, document_url);
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->lock_screen.is_null());
    EXPECT_EQ("https://foo.com/", manifest->lock_screen->start_url.GetString());
  }

  {
    // A valid lock_screen start_url entry, parsed relative to manifest URL.
    auto& manifest = ParseManifestWithURLs(
        R"({
          "lock_screen": {
            "start_url": "new_note"
          }
        })",
        manifest_url, document_url);
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->lock_screen.is_null());
    EXPECT_EQ("https://foo.com/new_note",
              manifest->lock_screen->start_url.GetString());
  }
}

TEST_F(ManifestParserTest, NoteTakingParseRules) {
  KURL manifest_url = KURL("https://foo.com/manifest.json");
  KURL document_url = KURL("https://foo.com/index.html");

  {
    // Manifest does not contain a 'note_taking' field.
    auto& manifest = ParseManifest("{ }");
    ASSERT_EQ(0u, GetErrorCount());
    EXPECT_TRUE(manifest->note_taking.is_null());
  }

  {
    // 'note_taking' is not an object.
    auto& manifest = ParseManifest(R"( { "note_taking": [ ] } )");
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'note_taking' ignored, type object expected.",
              errors()[0]);
    EXPECT_TRUE(manifest->note_taking.is_null());
  }

  {
    // Contains 'note_taking' field but no new_note_url entry.
    auto& manifest = ParseManifest(R"( { "note_taking": { } } )");
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->note_taking.is_null());
    EXPECT_TRUE(manifest->note_taking->new_note_url.IsEmpty());
  }

  {
    // 'new_note_url' entries must be valid URLs.
    auto& manifest =
        ParseManifest(R"({ "note_taking": { "new_note_url": {} } } )");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'new_note_url' ignored, type string expected.",
              errors()[0]);
    ASSERT_FALSE(manifest->note_taking.is_null());
    EXPECT_TRUE(manifest->note_taking->new_note_url.IsEmpty());
  }

  {
    // 'new_note_url' entries must be within scope.
    auto& manifest = ParseManifest(
        R"({ "note_taking": { "new_note_url": "https://bar.com" } } )");
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'new_note_url' ignored, should be within scope of the "
        "manifest.",
        errors()[0]);
    ASSERT_FALSE(manifest->note_taking.is_null());
    EXPECT_TRUE(manifest->note_taking->new_note_url.IsEmpty());
  }

  {
    // A valid note_taking new_note_url entry.
    auto& manifest = ParseManifestWithURLs(
        R"({
          "note_taking": {
            "new_note_url": "https://foo.com"
          }
        })",
        manifest_url, document_url);
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->note_taking.is_null());
    EXPECT_EQ("https://foo.com/",
              manifest->note_taking->new_note_url.GetString());
  }

  {
    // A valid note_taking new_note_url entry, parsed relative to manifest URL.
    auto& manifest = ParseManifestWithURLs(
        R"({
          "note_taking": {
            "new_note_url": "new_note"
          }
        })",
        manifest_url, document_url);
    ASSERT_EQ(0u, GetErrorCount());
    ASSERT_FALSE(manifest->note_taking.is_null());
    EXPECT_EQ("https://foo.com/new_note",
              manifest->note_taking->new_note_url.GetString());
  }
}

TEST_F(ManifestParserTest, ShareTargetParseRules) {
  // Contains share_target field but no keys.
  {
    auto& manifest = ParseManifest(R"({ "share_target": {} })");
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[0]);
  }

  // Contains share_target field but no params key.
  {
    auto& manifest = ParseManifest(R"({ "share_target": { "action": "" } })");
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ(
        "property 'share_target' ignored. Property 'params' type "
        "dictionary expected.",
        errors()[2]);
  }

  // Contains share_target field but no action key.
  {
    auto& manifest = ParseManifest(R"({ "share_target": { "params": {} } })");
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[0]);
  }

  // Key in share_target that isn't valid.
  {
    auto& manifest = ParseManifest(
        R"({ "share_target": {"incorrect_key": "some_value" } })");
    ASSERT_FALSE(manifest->share_target.get());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShareTargetUrlTemplateParseRules) {
  KURL manifest_url = KURL("https://foo.com/manifest.json");
  KURL document_url = KURL("https://foo.com/index.html");

  // Contains share_target, but action is empty.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": {} } })", manifest_url,
        document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action, manifest_url);
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
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

  // Parse but throw an error if url_template property isn't a string.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": {} } })", manifest_url,
        document_url);
    EXPECT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action, manifest_url);
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
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

  // Don't parse if action property isn't a string.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": {}, "params": {} } })", manifest_url,
        document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'action' ignored, type string expected.", errors()[0]);
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[1]);
  }

  // Don't parse if action property isn't a string.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": 42, "params": {} } })", manifest_url,
        document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'action' ignored, type string expected.", errors()[0]);
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[1]);
  }

  // Don't parse if params property isn't a dict.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": "" } })", manifest_url,
        document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ(
        "property 'share_target' ignored. Property 'params' type "
        "dictionary expected.",
        errors()[2]);
  }

  // Don't parse if params property isn't a dict.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": 42 } })", manifest_url,
        document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ(
        "property 'share_target' ignored. Property 'params' type "
        "dictionary expected.",
        errors()[2]);
  }

  // Ignore params keys with invalid types.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": { "text": 42 }
         } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action, manifest_url);
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ("property 'text' ignored, type string expected.", errors()[2]);
  }

  // Ignore params keys with invalid types.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "",
        "params": { "title": 42 } } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action, manifest_url);
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ("property 'title' ignored, type string expected.", errors()[2]);
  }

  // Don't parse if params property has keys with invalid types.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "", "params": { "url": {},
        "text": "hi" } } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action, manifest_url);
    EXPECT_EQ(manifest->share_target->params->text, "hi");
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(3u, GetErrorCount());
    EXPECT_EQ(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.",
        errors()[0]);
    EXPECT_EQ(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded",
        errors()[1]);
    EXPECT_EQ("property 'url' ignored, type string expected.", errors()[2]);
  }

  // Don't parse if action property isn't a valid URL.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com:a", "params":
        {} } })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ("property 'action' ignored, URL is invalid.", errors()[0]);
    EXPECT_EQ("property 'share_target' ignored. Property 'action' is invalid.",
              errors()[1]);
  }

  // Fail parsing if action is at a different origin than the Web
  // manifest.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo2.com/",
        "params": {} } })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'action' ignored, should be within scope of the manifest.",
        errors()[0]);
    EXPECT_EQ(
        "property 'share_target' ignored. Property 'action' is "
        "invalid.",
        errors()[1]);
  }

  // Fail parsing if action is not within scope of the manifest.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "start_url": "/app/",
          "scope": "/app/",
          "share_target": { "action": "/",
        "params": {} } })",
        manifest_url, document_url);
    EXPECT_FALSE(manifest->share_target.get());
    EXPECT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'action' ignored, should be within scope of the manifest.",
        errors()[0]);
    EXPECT_EQ(
        "property 'share_target' ignored. Property 'action' is "
        "invalid.",
        errors()[1]);
  }

  // Smoke test: Contains share_target and action, and action is valid.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": {"action": "share/", "params": {} } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action.GetString(),
              "https://foo.com/share/");
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_TRUE(manifest->share_target->params->title.IsNull());
    EXPECT_TRUE(manifest->share_target->params->url.IsNull());
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

  // Smoke test: Contains share_target and action, and action is valid, params
  // is populated.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": {"action": "share/", "params": { "text":
        "foo", "title": "bar", "url": "baz" } } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action.GetString(),
              "https://foo.com/share/");
    EXPECT_EQ(manifest->share_target->params->text, "foo");
    EXPECT_EQ(manifest->share_target->params->title, "bar");
    EXPECT_EQ(manifest->share_target->params->url, "baz");
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

  // Backwards compatibility test: Contains share_target, url_template and
  // action, and action is valid, params is populated.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "url_template":
        "foo.com/share?title={title}",
        "action": "share/", "params": { "text":
        "foo", "title": "bar", "url": "baz" } } })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action.GetString(),
              "https://foo.com/share/");
    EXPECT_EQ(manifest->share_target->params->text, "foo");
    EXPECT_EQ(manifest->share_target->params->title, "bar");
    EXPECT_EQ(manifest->share_target->params->url, "baz");
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

  // Smoke test: Contains share_target, action and params. action is
  // valid and is absolute.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "share_target": { "action": "https://foo.com/#", "params":
        { "title": "mytitle" } }
        })",
        manifest_url, document_url);
    ASSERT_TRUE(manifest->share_target.get());
    EXPECT_EQ(manifest->share_target->action.GetString(), "https://foo.com/#");
    EXPECT_TRUE(manifest->share_target->params->text.IsNull());
    EXPECT_EQ(manifest->share_target->params->title, "mytitle");
    EXPECT_TRUE(
```