Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file (`blink/renderer/modules/manifest/manifest_parser.cc`). This snippet focuses on parsing specific sections of a web app manifest file.

Here's a breakdown of the functions and their purpose:

1. **`ParseScreenshots`**:  Parses the `screenshots` array in the manifest. Extracts image information (source, type, sizes), form factor, and label for each screenshot.
2. **`ParseImageResourceArray`**: Parses arrays of image resources, used for properties like `icons`.
3. **`ParseImageResource`**: Parses a single image resource object, extracting `src`, `type`, `sizes`, and `purpose`.
4. **`ParseShortcutName`, `ParseShortcutShortName`, `ParseShortcutDescription`, `ParseShortcutUrl`**:  Parse individual properties of a `shortcut` object within the manifest.
5. **`ParseShortcuts`**: Parses the `shortcuts` array, extracting information for each shortcut, including its URL, name, short name, description, and associated icons. It also limits the number of shortcuts parsed.
6. **`ParseFileFilterName`, `ParseFileFilterAccept`**:  Parse the `name` and `accept` properties within a file filter object. The `accept` property can be a string or an array of strings representing accepted file types.
7. **`ParseTargetFiles`**: Parses an array of file filter objects (or a single file filter object), often used in the context of share targets.
8. **`ParseFileFilter`**: Parses a single file filter object, extracting its name and accepted file types.
9. **`ParseShareTargetMethod`, `ParseShareTargetEnctype`**: Parse the `method` (GET or POST) and `enctype` (form URL-encoded or multipart) of a share target.
10. **`ParseShareTargetParams`**: Parses the `params` section of a share target, extracting the `text`, `title`, `url`, and `files` properties.
11. **`ParseShareTarget`**: Parses the `share_target` object, including its `action`, `method`, `enctype`, and `params`. It also performs validation based on the chosen method and enctype.
12. **`ParseFileHandlers`**: Parses the `file_handlers` array, iterating through each file handler entry.
13. **`ParseFileHandler`**: Parses a single file handler object, extracting its `action`, `name`, `icons`, `accept` types, and `launch_type`.
14. **`ParseFileHandlerAccept`**: Parses the `accept` property of a file handler, which is a dictionary of MIME types and their associated file extensions. It also enforces a limit on the total number of file extensions.
15. **`ParseFileHandlerAcceptExtension`**: Validates and extracts a single file extension string.
16. **`ParseProtocolHandlers`**: Parses the `protocol_handlers` array, extracting information for each custom protocol handler.
17. **`ParseProtocolHandler`**: Parses a single protocol handler object, extracting the `protocol` and `url`. It also validates the protocol and URL syntax.
18. **`ParseUrlHandlers`**: Parses the `url_handlers` array, extracting information for each URL handler. This feature might be behind a flag.
19. **`ParseUrlHandler`**: Parses a single URL handler object, extracting the `origin` and handling wildcard origins.
20. **`ParseScopeExtensions`**: Parses the `scope_extensions` array, which can contain strings or objects defining extended scopes. This feature might be behind a flag.
21. **`ParseScopeExtension`**: Parses a scope extension object, extracting the `origin`.
22. **`ParseScopeExtensionOrigin`**: Parses a scope extension origin string, handling wildcard origins.
23. **`ParseLockScreenStartUrl`**: Parses the `start_url` property within the `lock_screen` object.
24. **`ParseLockScreen`**: Parses the `lock_screen` object in the manifest.
25. **`ParseNoteTakingNewNoteUrl`**: (Incomplete snippet) Likely intended to parse the `new_note_url` within a `note_taking` object.

The code consistently uses JSON parsing methods (`Get`, `GetArray`, `GetString`, `GetJSONObject`) to extract data from the manifest. It also uses `AddErrorInfo` to report errors encountered during parsing. The parsed data is typically stored in `mojom::blink` data structures.

**Relationships with Javascript, HTML, and CSS:**

*   **Javascript:** This code parses the web app manifest, which is often referenced in the HTML using a `<link rel="manifest" href="manifest.json">` tag. Javascript code running in the browser can access the parsed manifest data to understand the app's properties and capabilities. For instance, a Javascript application might check the `shortcuts` to offer quick actions to the user or use the `share_target` information to enable sharing functionality.
*   **HTML:** The manifest provides metadata about the web application, influencing how the browser displays and treats the application. Information like `icons`, `name`, `short_name`, `description`, and `screenshots` are used to present the app to the user (e.g., on the home screen, in app switchers). The `start_url` defines the entry point of the application.
*   **CSS:** While the manifest itself doesn't directly relate to CSS in terms of parsing CSS syntax, some manifest properties can influence the visual presentation. For example, the `theme_color` property can set the color of the browser's toolbar. The `display` property can define the app's display mode (fullscreen, standalone, etc.), affecting the UI elements provided by the browser.

**Hypothetical Input and Output (for `ParseShortcuts`):**

**Input (JSON snippet within the manifest):**

```json
"shortcuts": [
  {
    "name": "Open Inbox",
    "short_name": "Inbox",
    "description": "View your email inbox",
    "url": "/inbox"
  },
  {
    "name": "Compose Email",
    "url": "/compose"
  }
]
```

**Output (C++ `Vector<mojom::blink::ManifestShortcutItemPtr>`):**

The function would return a vector containing two `ManifestShortcutItemPtr` objects.

*   The first object would have:
    *   `url`:  A `KURL` object representing `/inbox` resolved against the manifest URL.
    *   `name`: `"Open Inbox"`
    *   `short_name`: `"Inbox"`
    *   `description`: `"View your email inbox"`
    *   `icons`: An empty vector (no icons provided in the input).

*   The second object would have:
    *   `url`: A `KURL` object representing `/compose` resolved against the manifest URL.
    *   `name`: `"Compose Email"`
    *   `short_name`: `""` (empty string as it's optional)
    *   `description`: `""` (empty string as it's optional)
    *   `icons`: An empty vector.

**Common User/Programming Errors:**

*   **Incorrect JSON Syntax:**  A common error is having invalid JSON in the manifest file (e.g., missing commas, unquoted strings). This would likely cause the entire parsing process to fail early on, before reaching these specific functions.
*   **Incorrect Data Types:** As seen in the code, the parser expects specific data types for manifest properties. Providing the wrong type (e.g., a string instead of an array for `screenshots`) will lead to errors and the property being ignored. The `AddErrorInfo` calls are used to report these.
    *   **Example:** Providing `"screenshots": "image.png"` instead of `"screenshots": [{"src": "image.png"}]`. The `ParseScreenshots` function would log an error "property 'screenshots' ignored, type array expected."
*   **Missing Required Fields:** Some manifest properties are mandatory. If a required field is missing, the parsing will fail or the corresponding feature might not work as expected.
    *   **Example:** In a `shortcut` object, the `name` is required. If it's missing, the shortcut will be ignored, and `ParseShortcuts` will skip it.
*   **Invalid URLs:** URLs provided in the manifest must be valid. The `ParseURL` function handles URL parsing and validation, and errors will be reported if a URL is malformed.
    *   **Example:**  A `shortcut` with `"url": "invalid-url"` would be flagged as an error by `ParseShortcutUrl`.
*   **Incorrect File Extensions in `accept`:** When defining file handlers, the extensions in the `accept` property must start with a ".".
    *   **Example:** `"accept": {"image/png": ["png"]}` would cause an error "property 'accept' file extension ignored, must start with a '.'." in `ParseFileHandlerAcceptExtension`.

**User Operations Leading to This Code (Debugging Clues):**

1. **Developer creates a web application and a `manifest.json` file.** This file contains the metadata about the application.
2. **Developer links the manifest file in the HTML using `<link rel="manifest" href="manifest.json">`.**
3. **User opens the web application in a Chromium-based browser.**
4. **The browser fetches the `manifest.json` file.**
5. **The browser starts parsing the manifest file.** This is where `ManifestParser` comes into play.
6. **The JSON content of the manifest is processed, and the relevant sections are passed to functions like `ParseScreenshots`, `ParseShortcuts`, `ParseShareTarget`, etc.**
7. **If there are errors in the manifest, the `AddErrorInfo` calls will log messages to the developer console (or internal browser logs).**

**Summary of Functionality (for Part 2):**

This section of `manifest_parser.cc` is responsible for parsing various object types within a web app manifest file, focusing on:

*   **Visual elements:**  Screenshots and icons.
*   **App shortcuts:**  Defining quick actions users can take.
*   **Share targets:**  Enabling the app to receive shared content.
*   **File handling:**  Declaring the types of files the app can handle.
*   **Protocol handling:**  Registering the app as a handler for custom protocols.
*   **URL handling:** Defining origins that the app can handle.
*   **Scope extensions:**  Defining origins that are considered part of the app's scope.
*   **Lock screen integration:** Defining a start URL for lock screen shortcuts.

It extracts structured data from the JSON manifest and converts it into internal Blink data structures (`mojom::blink::*`), performing validation and error reporting along the way. This parsed information is then used by the browser to integrate the web application with the operating system and provide enhanced user experiences.

这是 `blink/renderer/modules/manifest/manifest_parser.cc` 源代码文件的第二部分，主要负责解析 Web App Manifest 文件中关于以下功能特性的 JSON 结构：

**功能归纳:**

*   **Screenshots:** 解析 `screenshots` 属性，提取应用截图的信息，包括图片资源、展示的设备类型和标签。
*   **图标 (Icons):** 解析 `icons` 相关的属性，包括应用的图标资源及其各种属性 (src, type, sizes, purpose)。
*   **快捷方式 (Shortcuts):** 解析 `shortcuts` 属性，提取应用快捷方式的信息，包括名称、短名称、描述、URL 和关联的图标。
*   **文件过滤器 (File Filters):** 解析用于文件处理和分享目标中的文件过滤器定义，包括名称和接受的文件类型。
*   **分享目标 (Share Target):** 解析 `share_target` 属性，提取应用作为分享目标的相关信息，包括处理分享的 URL (action)、HTTP 方法 (method)、编码类型 (enctype) 和参数 (params)。
*   **文件处理器 (File Handlers):** 解析 `file_handlers` 属性，提取应用可以处理的文件类型和对应的处理 URL。
*   **协议处理器 (Protocol Handlers):** 解析 `protocol_handlers` 属性，提取应用可以处理的自定义协议及其处理 URL。
*   **URL 处理器 (URL Handlers):** 解析 `url_handlers` 属性，提取应用可以处理的特定来源的 URL。
*   **Scope 扩展 (Scope Extensions):** 解析 `scope_extensions` 属性，提取被视为应用作用域扩展的来源。
*   **锁屏 (Lock Screen):** 解析 `lock_screen` 属性，提取在锁屏上启动应用的 URL。
*   **笔记 (Note Taking):** (代码片段不完整，但可以推测) 可能是解析与笔记功能相关的属性，例如创建新笔记的 URL。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这些解析的功能都直接关系到 Web App Manifest 的定义，而 Manifest 文件是通过 HTML 中的 `<link rel="manifest" href="manifest.json">` 标签引入的。Javascript 代码可以通过浏览器提供的 API (例如 `navigator.getInstalledRelatedApps()`)  获取并利用 Manifest 中的信息。

*   **Javascript:**  Javascript 可以访问 Manifest 中解析出的 `shortcuts`，从而动态创建应用内的快捷方式入口，或者根据 `share_target` 的信息实现分享功能。
    *   **举例:**  一个 PWA 应用的 Javascript 代码可以读取 `manifest.json` 中定义的 `share_target`，然后在用户点击分享按钮时，根据 Manifest 中的 `action`, `method` 和 `params` 构建分享请求。
*   **HTML:** Manifest 中的信息直接影响浏览器如何渲染和处理 Web 应用。例如，`icons` 用于在安装时生成桌面图标，`name` 和 `short_name` 用于显示应用名称，`screenshots` 可以用于展示应用预览。
    *   **举例:**  浏览器会根据 `manifest.json` 中 `icons` 数组里的信息，选择合适的图标尺寸显示在用户的桌面或应用启动器中。
*   **CSS:** Manifest 中的某些属性，如 `theme_color`，可以直接影响浏览器提供的 UI 元素的样式。
    *   **举例:**  在 `manifest.json` 中设置了 `theme_color: "#4285f4"`，那么某些浏览器可能会将地址栏或任务栏的颜色设置为蓝色。

**逻辑推理的假设输入与输出:**

**假设输入 (manifest.json 中 "shortcuts" 部分):**

```json
{
  "shortcuts": [
    {
      "name": "发送邮件",
      "short_name": "邮件",
      "url": "/compose",
      "icons": [
        {
          "src": "/icons/compose.png",
          "sizes": "192x192",
          "type": "image/png"
        }
      ]
    }
  ]
}
```

**输出 (C++ 代码 `ParseShortcuts` 函数的输出):**

`ParseShortcuts` 函数会返回一个包含 `mojom::blink::ManifestShortcutItemPtr` 元素的 `Vector`。在这个例子中，`Vector` 将包含一个元素，该元素对应的 `ManifestShortcutItemPtr` 对象会包含以下信息：

*   `url`: 一个 `KURL` 对象，其值为基于 Manifest 文件 URL 解析出的 `/compose` 完整 URL。
*   `name`: `"发送邮件"`
*   `short_name`: `"邮件"`
*   `description`: `""` (因为输入中没有提供 description)
*   `icons`: 一个包含一个 `mojom::blink::ManifestImageResourcePtr` 元素的 `Vector`，该元素包含以下信息：
    *   `src`: 一个 `KURL` 对象，其值为基于 Manifest 文件 URL 解析出的 `/icons/compose.png` 完整 URL。
    *   `sizes`: `SkISize::Make(192, 192)`
    *   `type`: `"image/png"`
    *   `purpose`:  默认值 (通常为空或未定义，除非在输入中明确指定)

**用户或编程常见的使用错误举例说明:**

*   **JSON 格式错误:** Manifest 文件不是有效的 JSON 格式，例如缺少逗号、引号不匹配等。
    *   **例子:** `"shortcuts": [{ "name": "Open" "url": "/open" }]` (缺少逗号)。`ManifestParser` 在解析 JSON 时会报错，导致整个 Manifest 解析失败。
*   **属性类型错误:**  Manifest 文件中某个属性的值类型与预期不符。
    *   **例子:** `"screenshots": "image.png"` (预期 `screenshots` 是一个数组)。`ParseScreenshots` 函数会检查类型，发现不是数组，会调用 `AddErrorInfo` 记录错误，并返回空的 `screenshots` 向量。
*   **缺少必需的属性:**  某些 Manifest 属性是必需的，如果缺失会导致解析错误或功能不完整。
    *   **例子:**  在 `shortcuts` 中的一个条目缺少 `url` 属性。`ParseShortcutUrl` 函数会发现 `url` 为空，调用 `AddErrorInfo` 记录错误。`ParseShortcuts` 会忽略这个无效的快捷方式条目。
*   **URL 格式错误:** Manifest 文件中的 URL 不是有效的 URL 格式。
    *   **例子:** `"url": "invalid-url"`。`ParseURL` 函数会尝试解析 URL，如果解析失败，会调用 `AddErrorInfo` 记录错误，并返回一个无效的 `KURL` 对象。
*   **`accept` 属性中文件扩展名格式错误:** 在文件处理器中，`accept` 属性中的文件扩展名必须以 "." 开头。
    *   **例子:** `"accept": {"image/png": ["png"]}`。`ParseFileHandlerAcceptExtension` 会检查扩展名是否以 "." 开头，如果不符合会调用 `AddErrorInfo` 记录错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者创建了一个 Web 应用并编写了 `manifest.json` 文件。**
2. **开发者在 Web 应用的 HTML 文件中添加了 `<link rel="manifest" href="manifest.json">` 标签。**
3. **用户在 Chromium 内核的浏览器中访问了这个 Web 应用。**
4. **浏览器开始解析 HTML 页面，并发现了 `<link rel="manifest">` 标签。**
5. **浏览器发起网络请求去获取 `manifest.json` 文件。**
6. **浏览器接收到 `manifest.json` 的内容后，开始进行 Manifest 文件的解析。**
7. **`ManifestParser` 类的实例被创建，并开始解析 JSON 数据。**
8. **JSON 数据中关于 `screenshots`、`icons`、`shortcuts` 等部分会被传递给对应的解析函数，例如 `ParseScreenshots`、`ParseImageResourceArray`、`ParseShortcuts` 等。**
9. **如果在解析过程中遇到任何格式错误、类型不匹配或缺失的必要属性，对应的 `AddErrorInfo` 函数会被调用，记录错误信息。**

作为调试线索，当开发者发现 Web 应用的某些 Manifest 功能没有按预期工作时 (例如，快捷方式没有显示，分享功能异常)，可以检查浏览器的开发者工具中的 "Console" 选项卡，查看是否有 `AddErrorInfo` 记录的错误信息，这些信息能帮助开发者定位 Manifest 文件中的问题。此外，开发者可以逐步检查 Manifest 文件中相关属性的 JSON 结构是否符合规范，数据类型是否正确。

### 提示词
```
这是目录为blink/renderer/modules/manifest/manifest_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ue* json_value = object->Get("screenshots");
  if (!json_value) {
    return screenshots;
  }

  JSONArray* screenshots_list = object->GetArray("screenshots");
  if (!screenshots_list) {
    AddErrorInfo("property 'screenshots' ignored, type array expected.");
    return screenshots;
  }

  for (wtf_size_t i = 0; i < screenshots_list->size(); ++i) {
    JSONObject* screenshot_object = JSONObject::Cast(screenshots_list->at(i));
    if (!screenshot_object) {
      continue;
    }

    auto screenshot = mojom::blink::ManifestScreenshot::New();
    auto image = ParseImageResource(screenshot_object);
    if (!image.has_value()) {
      continue;
    }

    screenshot->image = std::move(*image);
    screenshot->form_factor = ParseScreenshotFormFactor(screenshot_object);
    screenshot->label = ParseScreenshotLabel(screenshot_object);

    screenshots.push_back(std::move(screenshot));
  }

  return screenshots;
}

Vector<mojom::blink::ManifestImageResourcePtr>
ManifestParser::ParseImageResourceArray(const String& key,
                                        const JSONObject* object) {
  Vector<mojom::blink::ManifestImageResourcePtr> icons;
  JSONValue* json_value = object->Get(key);
  if (!json_value) {
    return icons;
  }

  JSONArray* icons_list = object->GetArray(key);
  if (!icons_list) {
    AddErrorInfo("property '" + key + "' ignored, type array expected.");
    return icons;
  }

  for (wtf_size_t i = 0; i < icons_list->size(); ++i) {
    auto icon = ParseImageResource(icons_list->at(i));
    if (icon.has_value()) {
      icons.push_back(std::move(*icon));
    }
  }

  return icons;
}

std::optional<mojom::blink::ManifestImageResourcePtr>
ManifestParser::ParseImageResource(const JSONValue* object) {
  const JSONObject* icon_object = JSONObject::Cast(object);
  if (!icon_object) {
    return std::nullopt;
  }

  auto icon = mojom::blink::ManifestImageResource::New();
  icon->src = ParseIconSrc(icon_object);
  // An icon MUST have a valid src. If it does not, it MUST be ignored.
  if (!icon->src.IsValid()) {
    return std::nullopt;
  }

  icon->type = ParseIconType(icon_object);
  icon->sizes = ParseIconSizes(icon_object);
  auto purpose = ParseIconPurpose(icon_object);
  if (!purpose) {
    return std::nullopt;
  }

  icon->purpose = std::move(*purpose);
  return icon;
}

String ManifestParser::ParseShortcutName(const JSONObject* shortcut) {
  std::optional<String> name =
      ParseStringForMember(shortcut, "shortcut", "name", true, Trim(true));
  return name.has_value() ? *name : String();
}

String ManifestParser::ParseShortcutShortName(const JSONObject* shortcut) {
  std::optional<String> short_name = ParseStringForMember(
      shortcut, "shortcut", "short_name", false, Trim(true));
  return short_name.has_value() ? *short_name : String();
}

String ManifestParser::ParseShortcutDescription(const JSONObject* shortcut) {
  std::optional<String> description = ParseStringForMember(
      shortcut, "shortcut", "description", false, Trim(true));
  return description.has_value() ? *description : String();
}

KURL ManifestParser::ParseShortcutUrl(const JSONObject* shortcut) {
  KURL shortcut_url = ParseURL(shortcut, "url", manifest_url_,
                               ParseURLRestrictions::kWithinScope);
  if (shortcut_url.IsNull()) {
    AddErrorInfo("property 'url' of 'shortcut' not present.");
  }

  return shortcut_url;
}

Vector<mojom::blink::ManifestShortcutItemPtr> ManifestParser::ParseShortcuts(
    const JSONObject* object) {
  Vector<mojom::blink::ManifestShortcutItemPtr> shortcuts;
  JSONValue* json_value = object->Get("shortcuts");
  if (!json_value) {
    return shortcuts;
  }

  JSONArray* shortcuts_list = object->GetArray("shortcuts");
  if (!shortcuts_list) {
    AddErrorInfo("property 'shortcuts' ignored, type array expected.");
    return shortcuts;
  }

  for (wtf_size_t i = 0; i < shortcuts_list->size(); ++i) {
    if (i == kMaxShortcutsSize) {
      AddErrorInfo("property 'shortcuts' contains more than " +
                   String::Number(kMaxShortcutsSize) +
                   " valid elements, only the first " +
                   String::Number(kMaxShortcutsSize) + " are parsed.");
      break;
    }

    JSONObject* shortcut_object = JSONObject::Cast(shortcuts_list->at(i));
    if (!shortcut_object) {
      continue;
    }

    auto shortcut = mojom::blink::ManifestShortcutItem::New();
    shortcut->url = ParseShortcutUrl(shortcut_object);
    // A shortcut MUST have a valid url. If it does not, it MUST be ignored.
    if (!shortcut->url.IsValid()) {
      continue;
    }

    // A shortcut MUST have a valid name. If it does not, it MUST be ignored.
    shortcut->name = ParseShortcutName(shortcut_object);
    if (shortcut->name == String()) {
      continue;
    }

    shortcut->short_name = ParseShortcutShortName(shortcut_object);
    shortcut->description = ParseShortcutDescription(shortcut_object);
    auto icons = ParseIcons(shortcut_object);
    if (!icons.empty()) {
      shortcut->icons = std::move(icons);
    }

    shortcuts.push_back(std::move(shortcut));
  }

  return shortcuts;
}

String ManifestParser::ParseFileFilterName(const JSONObject* file) {
  if (!file->Get("name")) {
    AddErrorInfo("property 'name' missing.");
    return String("");
  }

  String value;
  if (!file->GetString("name", &value)) {
    AddErrorInfo("property 'name' ignored, type string expected.");
    return String("");
  }
  return value;
}

Vector<String> ManifestParser::ParseFileFilterAccept(const JSONObject* object) {
  Vector<String> accept_types;
  if (!object->Get("accept")) {
    return accept_types;
  }

  String accept_str;
  if (object->GetString("accept", &accept_str)) {
    accept_types.push_back(accept_str);
    return accept_types;
  }

  JSONArray* accept_list = object->GetArray("accept");
  if (!accept_list) {
    // 'accept' property is the wrong type. Returning an empty vector here
    // causes the 'files' entry to be discarded.
    AddErrorInfo("property 'accept' ignored, type array or string expected.");
    return accept_types;
  }

  for (wtf_size_t i = 0; i < accept_list->size(); ++i) {
    JSONValue* accept_value = accept_list->at(i);
    String accept_string;
    if (!accept_value || !accept_value->AsString(&accept_string)) {
      // A particular 'accept' entry is invalid - just drop that one entry.
      AddErrorInfo("'accept' entry ignored, expected to be of type string.");
      continue;
    }
    accept_types.push_back(accept_string);
  }

  return accept_types;
}

Vector<mojom::blink::ManifestFileFilterPtr> ManifestParser::ParseTargetFiles(
    const String& key,
    const JSONObject* from) {
  Vector<mojom::blink::ManifestFileFilterPtr> files;
  if (!from->Get(key)) {
    return files;
  }

  JSONArray* file_list = from->GetArray(key);
  if (!file_list) {
    // https://wicg.github.io/web-share-target/level-2/#share_target-member
    // step 5 indicates that the 'files' attribute is allowed to be a single
    // (non-array) FileFilter.
    const JSONObject* file_object = from->GetJSONObject(key);
    if (!file_object) {
      AddErrorInfo(
          "property 'files' ignored, type array or FileFilter expected.");
      return files;
    }

    ParseFileFilter(file_object, &files);
    return files;
  }
  for (wtf_size_t i = 0; i < file_list->size(); ++i) {
    const JSONObject* file_object = JSONObject::Cast(file_list->at(i));
    if (!file_object) {
      AddErrorInfo("files must be a sequence of non-empty file entries.");
      continue;
    }

    ParseFileFilter(file_object, &files);
  }

  return files;
}

void ManifestParser::ParseFileFilter(
    const JSONObject* file_object,
    Vector<mojom::blink::ManifestFileFilterPtr>* files) {
  auto file = mojom::blink::ManifestFileFilter::New();
  file->name = ParseFileFilterName(file_object);
  if (file->name.empty()) {
    // https://wicg.github.io/web-share-target/level-2/#share_target-member
    // step 7.1 requires that we invalidate this FileFilter if 'name' is an
    // empty string. We also invalidate if 'name' is undefined or not a
    // string.
    return;
  }

  file->accept = ParseFileFilterAccept(file_object);
  if (file->accept.empty()) {
    return;
  }

  files->push_back(std::move(file));
}

std::optional<mojom::blink::ManifestShareTarget::Method>
ManifestParser::ParseShareTargetMethod(const JSONObject* share_target_object) {
  if (!share_target_object->Get("method")) {
    AddErrorInfo(
        "Method should be set to either GET or POST. It currently defaults to "
        "GET.");
    return mojom::blink::ManifestShareTarget::Method::kGet;
  }

  String value;
  if (!share_target_object->GetString("method", &value)) {
    return std::nullopt;
  }

  String method = value.UpperASCII();
  if (method == "GET") {
    return mojom::blink::ManifestShareTarget::Method::kGet;
  }
  if (method == "POST") {
    return mojom::blink::ManifestShareTarget::Method::kPost;
  }

  return std::nullopt;
}

std::optional<mojom::blink::ManifestShareTarget::Enctype>
ManifestParser::ParseShareTargetEnctype(const JSONObject* share_target_object) {
  if (!share_target_object->Get("enctype")) {
    AddErrorInfo(
        "Enctype should be set to either application/x-www-form-urlencoded or "
        "multipart/form-data. It currently defaults to "
        "application/x-www-form-urlencoded");
    return mojom::blink::ManifestShareTarget::Enctype::kFormUrlEncoded;
  }

  String value;
  if (!share_target_object->GetString("enctype", &value)) {
    return std::nullopt;
  }

  String enctype = value.LowerASCII();
  if (enctype == "application/x-www-form-urlencoded") {
    return mojom::blink::ManifestShareTarget::Enctype::kFormUrlEncoded;
  }

  if (enctype == "multipart/form-data") {
    return mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData;
  }

  return std::nullopt;
}

mojom::blink::ManifestShareTargetParamsPtr
ManifestParser::ParseShareTargetParams(const JSONObject* share_target_params) {
  auto params = mojom::blink::ManifestShareTargetParams::New();

  // NOTE: These are key names for query parameters, which are filled with share
  // data. As such, |params.url| is just a string.
  std::optional<String> text =
      ParseString(share_target_params, "text", Trim(true));
  params->text = text.has_value() ? *text : String();
  std::optional<String> title =
      ParseString(share_target_params, "title", Trim(true));
  params->title = title.has_value() ? *title : String();
  std::optional<String> url =
      ParseString(share_target_params, "url", Trim(true));
  params->url = url.has_value() ? *url : String();

  auto files = ParseTargetFiles("files", share_target_params);
  if (!files.empty()) {
    params->files = std::move(files);
  }
  return params;
}

std::optional<mojom::blink::ManifestShareTargetPtr>
ManifestParser::ParseShareTarget(const JSONObject* object) {
  const JSONObject* share_target_object = object->GetJSONObject("share_target");
  if (!share_target_object) {
    return std::nullopt;
  }

  auto share_target = mojom::blink::ManifestShareTarget::New();
  share_target->action = ParseURL(share_target_object, "action", manifest_url_,
                                  ParseURLRestrictions::kWithinScope);
  if (!share_target->action.IsValid()) {
    AddErrorInfo(
        "property 'share_target' ignored. Property 'action' is "
        "invalid.");
    return std::nullopt;
  }

  auto method = ParseShareTargetMethod(share_target_object);
  auto enctype = ParseShareTargetEnctype(share_target_object);

  const JSONObject* share_target_params_object =
      share_target_object->GetJSONObject("params");
  if (!share_target_params_object) {
    AddErrorInfo(
        "property 'share_target' ignored. Property 'params' type "
        "dictionary expected.");
    return std::nullopt;
  }

  share_target->params = ParseShareTargetParams(share_target_params_object);
  if (!method.has_value()) {
    AddErrorInfo(
        "invalid method. Allowed methods are:"
        "GET and POST.");
    return std::nullopt;
  }
  share_target->method = method.value();

  if (!enctype.has_value()) {
    AddErrorInfo(
        "invalid enctype. Allowed enctypes are:"
        "application/x-www-form-urlencoded and multipart/form-data.");
    return std::nullopt;
  }
  share_target->enctype = enctype.value();

  if (share_target->method == mojom::blink::ManifestShareTarget::Method::kGet) {
    if (share_target->enctype ==
        mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData) {
      AddErrorInfo(
          "invalid enctype for GET method. Only "
          "application/x-www-form-urlencoded is allowed.");
      return std::nullopt;
    }
  }

  if (share_target->params->files.has_value()) {
    if (share_target->method !=
            mojom::blink::ManifestShareTarget::Method::kPost ||
        share_target->enctype !=
            mojom::blink::ManifestShareTarget::Enctype::kMultipartFormData) {
      AddErrorInfo("files are only supported with multipart/form-data POST.");
      return std::nullopt;
    }
  }

  if (share_target->params->files.has_value() &&
      !VerifyFiles(*share_target->params->files)) {
    AddErrorInfo("invalid mime type inside files.");
    return std::nullopt;
  }

  return share_target;
}

Vector<mojom::blink::ManifestFileHandlerPtr> ManifestParser::ParseFileHandlers(
    const JSONObject* object) {
  if (!object->Get("file_handlers")) {
    return {};
  }

  JSONArray* entry_array = object->GetArray("file_handlers");
  if (!entry_array) {
    AddErrorInfo("property 'file_handlers' ignored, type array expected.");
    return {};
  }

  Vector<mojom::blink::ManifestFileHandlerPtr> result;
  for (wtf_size_t i = 0; i < entry_array->size(); ++i) {
    JSONObject* json_entry = JSONObject::Cast(entry_array->at(i));
    if (!json_entry) {
      AddErrorInfo("FileHandler ignored, type object expected.");
      continue;
    }

    std::optional<mojom::blink::ManifestFileHandlerPtr> entry =
        ParseFileHandler(json_entry);
    if (!entry) {
      continue;
    }

    result.push_back(std::move(entry.value()));
  }

  return result;
}

std::optional<mojom::blink::ManifestFileHandlerPtr>
ManifestParser::ParseFileHandler(const JSONObject* file_handler) {
  mojom::blink::ManifestFileHandlerPtr entry =
      mojom::blink::ManifestFileHandler::New();
  entry->action = ParseURL(file_handler, "action", manifest_url_,
                           ParseURLRestrictions::kWithinScope);
  if (!entry->action.IsValid()) {
    AddErrorInfo("FileHandler ignored. Property 'action' is invalid.");
    return std::nullopt;
  }

  entry->name = ParseString(file_handler, "name", Trim(true)).value_or("");
  const bool feature_enabled =
      base::FeatureList::IsEnabled(blink::features::kFileHandlingIcons) ||
      RuntimeEnabledFeatures::FileHandlingIconsEnabled(execution_context_);
  if (feature_enabled) {
    entry->icons = ParseIcons(file_handler);
  }

  entry->accept = ParseFileHandlerAccept(file_handler->GetJSONObject("accept"));
  if (entry->accept.empty()) {
    AddErrorInfo("FileHandler ignored. Property 'accept' is invalid.");
    return std::nullopt;
  }

  entry->launch_type =
      ParseFirstValidEnum<
          std::optional<mojom::blink::ManifestFileHandler::LaunchType>>(
          file_handler, "launch_type", &FileHandlerLaunchTypeFromString,
          /*invalid_value=*/std::nullopt)
          .value_or(
              mojom::blink::ManifestFileHandler::LaunchType::kSingleClient);

  return entry;
}

HashMap<String, Vector<String>> ManifestParser::ParseFileHandlerAccept(
    const JSONObject* accept) {
  HashMap<String, Vector<String>> result;
  if (!accept) {
    return result;
  }

  const int kExtensionLimit = g_file_handler_extension_limit_for_testing > 0
                                  ? g_file_handler_extension_limit_for_testing
                                  : kFileHandlerExtensionLimit;
  if (total_file_handler_extension_count_ > kExtensionLimit) {
    return result;
  }

  for (wtf_size_t i = 0; i < accept->size(); ++i) {
    JSONObject::Entry entry = accept->at(i);

    // Validate the MIME type.
    String& mimetype = entry.first;
    std::string top_level_mime_type;
    if (!net::ParseMimeTypeWithoutParameter(mimetype.Utf8(),
                                            &top_level_mime_type, nullptr) ||
        !net::IsValidTopLevelMimeType(top_level_mime_type)) {
      AddErrorInfo("invalid MIME type: " + mimetype);
      continue;
    }

    Vector<String> extensions;
    String extension;
    JSONArray* extensions_array = JSONArray::Cast(entry.second);
    if (extensions_array) {
      for (wtf_size_t j = 0; j < extensions_array->size(); ++j) {
        JSONValue* value = extensions_array->at(j);
        if (!value->AsString(&extension)) {
          AddErrorInfo(
              "property 'accept' file extension ignored, type string "
              "expected.");
          continue;
        }

        if (!ParseFileHandlerAcceptExtension(value, &extension)) {
          // Errors are added by ParseFileHandlerAcceptExtension.
          continue;
        }

        extensions.push_back(extension);
      }
    } else if (ParseFileHandlerAcceptExtension(entry.second, &extension)) {
      extensions.push_back(extension);
    } else {
      // Parsing errors will already have been added.
      continue;
    }

    total_file_handler_extension_count_ += extensions.size();
    int extension_overflow =
        total_file_handler_extension_count_ - kExtensionLimit;
    if (extension_overflow > 0) {
      auto erase_iter = extensions.end() - extension_overflow;
      AddErrorInfo(
          "property 'accept': too many total file extensions, ignoring "
          "extensions starting from \"" +
          *erase_iter + "\"");
      extensions.erase(erase_iter, extensions.end());
    }

    if (!extensions.empty()) {
      result.Set(mimetype, std::move(extensions));
    }

    if (extension_overflow > 0) {
      break;
    }
  }

  return result;
}

bool ManifestParser::ParseFileHandlerAcceptExtension(const JSONValue* extension,
                                                     String* output) {
  if (!extension->AsString(output)) {
    AddErrorInfo(
        "property 'accept' type ignored. File extensions must be type array or "
        "type string.");
    return false;
  }

  if (!output->StartsWith(".")) {
    AddErrorInfo(
        "property 'accept' file extension ignored, must start with a '.'.");
    return false;
  }

  return true;
}

Vector<mojom::blink::ManifestProtocolHandlerPtr>
ManifestParser::ParseProtocolHandlers(const JSONObject* from) {
  Vector<mojom::blink::ManifestProtocolHandlerPtr> protocols;

  if (!from->Get("protocol_handlers")) {
    return protocols;
  }

  JSONArray* protocol_list = from->GetArray("protocol_handlers");
  if (!protocol_list) {
    AddErrorInfo("property 'protocol_handlers' ignored, type array expected.");
    return protocols;
  }

  for (wtf_size_t i = 0; i < protocol_list->size(); ++i) {
    const JSONObject* protocol_object = JSONObject::Cast(protocol_list->at(i));
    if (!protocol_object) {
      AddErrorInfo("protocol_handlers entry ignored, type object expected.");
      continue;
    }

    std::optional<mojom::blink::ManifestProtocolHandlerPtr> protocol =
        ParseProtocolHandler(protocol_object);
    if (!protocol) {
      continue;
    }

    protocols.push_back(std::move(protocol.value()));
  }

  return protocols;
}

std::optional<mojom::blink::ManifestProtocolHandlerPtr>
ManifestParser::ParseProtocolHandler(const JSONObject* object) {
  if (!object->Get("protocol")) {
    AddErrorInfo(
        "protocol_handlers entry ignored, required property 'protocol' is "
        "missing.");
    return std::nullopt;
  }

  auto protocol_handler = mojom::blink::ManifestProtocolHandler::New();
  std::optional<String> protocol = ParseString(object, "protocol", Trim(true));
  String error_message;
  bool is_valid_protocol = protocol.has_value();

  if (is_valid_protocol &&
      !VerifyCustomHandlerScheme(protocol.value(), error_message,
                                 ProtocolHandlerSecurityLevel::kStrict)) {
    AddErrorInfo(error_message);
    is_valid_protocol = false;
  }

  if (!is_valid_protocol) {
    AddErrorInfo(
        "protocol_handlers entry ignored, required property 'protocol' is "
        "invalid.");
    return std::nullopt;
  }
  protocol_handler->protocol = protocol.value();

  if (!object->Get("url")) {
    AddErrorInfo(
        "protocol_handlers entry ignored, required property 'url' is missing.");
    return std::nullopt;
  }
  protocol_handler->url = ParseURL(object, "url", manifest_url_,
                                   ParseURLRestrictions::kWithinScope);
  bool is_valid_url = protocol_handler->url.IsValid();
  if (is_valid_url) {
    const char kToken[] = "%s";
    String user_url = protocol_handler->url.GetString();
    String tokenless_url = protocol_handler->url.GetString();
    tokenless_url.Remove(user_url.Find(kToken), std::size(kToken) - 1);
    KURL full_url(manifest_url_, tokenless_url);

    if (!VerifyCustomHandlerURLSyntax(full_url, manifest_url_, user_url,
                                      error_message)) {
      AddErrorInfo(error_message);
      is_valid_url = false;
    }
  }

  if (!is_valid_url) {
    AddErrorInfo(
        "protocol_handlers entry ignored, required property 'url' is invalid.");
    return std::nullopt;
  }

  return std::move(protocol_handler);
}

Vector<mojom::blink::ManifestUrlHandlerPtr> ManifestParser::ParseUrlHandlers(
    const JSONObject* from) {
  Vector<mojom::blink::ManifestUrlHandlerPtr> url_handlers;
  const bool feature_enabled =
      base::FeatureList::IsEnabled(blink::features::kWebAppEnableUrlHandlers) ||
      RuntimeEnabledFeatures::WebAppUrlHandlingEnabled(execution_context_);
  if (!feature_enabled || !from->Get("url_handlers")) {
    return url_handlers;
  }
  JSONArray* handlers_list = from->GetArray("url_handlers");
  if (!handlers_list) {
    AddErrorInfo("property 'url_handlers' ignored, type array expected.");
    return url_handlers;
  }
  for (wtf_size_t i = 0; i < handlers_list->size(); ++i) {
    if (i == kMaxUrlHandlersSize) {
      AddErrorInfo("property 'url_handlers' contains more than " +
                   String::Number(kMaxUrlHandlersSize) +
                   " valid elements, only the first " +
                   String::Number(kMaxUrlHandlersSize) + " are parsed.");
      break;
    }

    const JSONObject* handler_object = JSONObject::Cast(handlers_list->at(i));
    if (!handler_object) {
      AddErrorInfo("url_handlers entry ignored, type object expected.");
      continue;
    }

    std::optional<mojom::blink::ManifestUrlHandlerPtr> url_handler =
        ParseUrlHandler(handler_object);
    if (!url_handler) {
      continue;
    }
    url_handlers.push_back(std::move(url_handler.value()));
  }
  return url_handlers;
}

std::optional<mojom::blink::ManifestUrlHandlerPtr>
ManifestParser::ParseUrlHandler(const JSONObject* object) {
  DCHECK(
      base::FeatureList::IsEnabled(blink::features::kWebAppEnableUrlHandlers) ||
      RuntimeEnabledFeatures::WebAppUrlHandlingEnabled(execution_context_));
  if (!object->Get("origin")) {
    AddErrorInfo(
        "url_handlers entry ignored, required property 'origin' is missing.");
    return std::nullopt;
  }
  const std::optional<String> origin_string =
      ParseString(object, "origin", Trim(true));
  if (!origin_string.has_value()) {
    AddErrorInfo(
        "url_handlers entry ignored, required property 'origin' is invalid.");
    return std::nullopt;
  }

  // TODO(crbug.com/1072058): pre-process for input without scheme.
  // (eg. example.com instead of https://example.com) because we can always
  // assume the use of https for URL handling. Remove this TODO if we decide
  // to require fully specified https scheme in this origin input.

  if (origin_string->length() > kMaxOriginLength) {
    AddErrorInfo(
        "url_handlers entry ignored, 'origin' exceeds maximum character length "
        "of " +
        String::Number(kMaxOriginLength) + " .");
    return std::nullopt;
  }

  auto origin = SecurityOrigin::CreateFromString(*origin_string);
  if (!origin || origin->IsOpaque()) {
    AddErrorInfo(
        "url_handlers entry ignored, required property 'origin' is invalid.");
    return std::nullopt;
  }
  if (origin->Protocol() != url::kHttpsScheme) {
    AddErrorInfo(
        "url_handlers entry ignored, required property 'origin' must use the "
        "https scheme.");
    return std::nullopt;
  }

  String host = origin->Host();
  auto url_handler = mojom::blink::ManifestUrlHandler::New();
  // Check for wildcard *.
  if (host.StartsWith(kOriginWildcardPrefix)) {
    url_handler->has_origin_wildcard = true;
    // Trim the wildcard prefix to get the effective host. Minus one to exclude
    // the length of the null terminator.
    host = host.Substring(sizeof(kOriginWildcardPrefix) - 1);
  } else {
    url_handler->has_origin_wildcard = false;
  }

  bool host_valid = IsHostValidForScopeExtension(host);
  if (!host_valid) {
    AddErrorInfo(
        "url_handlers entry ignored, domain of required property 'origin' is "
        "invalid.");
    return std::nullopt;
  }

  if (url_handler->has_origin_wildcard) {
    origin = SecurityOrigin::CreateFromValidTuple(origin->Protocol(), host,
                                                  origin->Port());
    if (!origin_string.has_value()) {
      AddErrorInfo(
          "url_handlers entry ignored, required property 'origin' is invalid.");
      return std::nullopt;
    }
  }

  url_handler->origin = origin;
  return std::move(url_handler);
}

Vector<mojom::blink::ManifestScopeExtensionPtr>
ManifestParser::ParseScopeExtensions(const JSONObject* from) {
  Vector<mojom::blink::ManifestScopeExtensionPtr> scope_extensions;
  const bool feature_enabled =
      base::FeatureList::IsEnabled(
          blink::features::kWebAppEnableScopeExtensions) ||
      RuntimeEnabledFeatures::WebAppScopeExtensionsEnabled(execution_context_);
  if (!feature_enabled || !from->Get("scope_extensions")) {
    return scope_extensions;
  }

  JSONArray* extensions_list = from->GetArray("scope_extensions");
  if (!extensions_list) {
    AddErrorInfo("property 'scope_extensions' ignored, type array expected.");
    return scope_extensions;
  }

  JSONValue::ValueType expected_entry_type = JSONValue::kTypeNull;
  for (wtf_size_t i = 0; i < extensions_list->size(); ++i) {
    if (i == kMaxScopeExtensionsSize) {
      AddErrorInfo("property 'scope_extensions' contains more than " +
                   String::Number(kMaxScopeExtensionsSize) +
                   " valid elements, only the first " +
                   String::Number(kMaxScopeExtensionsSize) + " are parsed.");
      break;
    }

    const JSONValue* extensions_entry = extensions_list->at(i);
    if (!extensions_entry) {
      AddErrorInfo("scope_extensions entry ignored, entry is null.");
      continue;
    }

    JSONValue::ValueType entry_type = extensions_entry->GetType();
    if (entry_type != JSONValue::kTypeString &&
        entry_type != JSONValue::kTypeObject) {
      AddErrorInfo(
          "scope_extensions entry ignored, type string or object expected.");
      continue;
    }

    // Check whether first scope extension entry in the list is a string or
    // object to make sure that following entries have the same type, ignoring
    // entries that are null or other types.
    if (expected_entry_type != JSONValue::kTypeString &&
        expected_entry_type != JSONValue::kTypeObject) {
      expected_entry_type = entry_type;
    }

    std::optional<mojom::blink::ManifestScopeExtensionPtr> scope_extension =
        std::nullopt;
    if (expected_entry_type == JSONValue::kTypeString) {
      String scope_extension_origin;
      if (!extensions_entry->AsString(&scope_extension_origin)) {
        AddErrorInfo("scope_extensions entry ignored, type string expected.");
        continue;
      }
      scope_extension = ParseScopeExtensionOrigin(scope_extension_origin);
    } else {
      const JSONObject* extension_object = JSONObject::Cast(extensions_entry);
      if (!extension_object) {
        AddErrorInfo("scope_extensions entry ignored, type object expected.");
        continue;
      }
      scope_extension = ParseScopeExtension(extension_object);
    }

    if (!scope_extension) {
      continue;
    }
    scope_extensions.push_back(std::move(scope_extension.value()));
  }
  return scope_extensions;
}

std::optional<mojom::blink::ManifestScopeExtensionPtr>
ManifestParser::ParseScopeExtension(const JSONObject* object) {
  DCHECK(
      base::FeatureList::IsEnabled(
          blink::features::kWebAppEnableScopeExtensions) ||
      RuntimeEnabledFeatures::WebAppScopeExtensionsEnabled(execution_context_));
  if (!object->Get("origin")) {
    AddErrorInfo(
        "scope_extensions entry ignored, required property 'origin' is "
        "missing.");
    return std::nullopt;
  }
  const std::optional<String> origin_string =
      ParseString(object, "origin", Trim(true));
  if (!origin_string.has_value()) {
    return std::nullopt;
  }

  return ParseScopeExtensionOrigin(*origin_string);
}

std::optional<mojom::blink::ManifestScopeExtensionPtr>
ManifestParser::ParseScopeExtensionOrigin(const String& origin_string) {
  DCHECK(
      base::FeatureList::IsEnabled(
          blink::features::kWebAppEnableScopeExtensions) ||
      RuntimeEnabledFeatures::WebAppScopeExtensionsEnabled(execution_context_));

  // TODO(crbug.com/1250011): pre-process for input without scheme.
  // (eg. example.com instead of https://example.com) because we can always
  // assume the use of https for scope extensions. Remove this TODO if we decide
  // to require fully specified https scheme in this origin input.

  if (origin_string.length() > kMaxOriginLength) {
    AddErrorInfo(
        "scope_extensions entry ignored, 'origin' exceeds maximum character "
        "length of " +
        String::Number(kMaxOriginLength) + " .");
    return std::nullopt;
  }

  auto origin = SecurityOrigin::CreateFromString(origin_string);
  if (!origin || origin->IsOpaque()) {
    AddErrorInfo(
        "scope_extensions entry ignored, required property 'origin' is "
        "invalid.");
    return std::nullopt;
  }
  if (origin->Protocol() != url::kHttpsScheme) {
    AddErrorInfo(
        "scope_extensions entry ignored, required property 'origin' must use "
        "the https scheme.");
    return std::nullopt;
  }

  String host = origin->Host();
  auto scope_extension = mojom::blink::ManifestScopeExtension::New();
  // Check for wildcard *.
  if (host.StartsWith(kOriginWildcardPrefix)) {
    scope_extension->has_origin_wildcard = true;
    // Trim the wildcard prefix to get the effective host. Minus one to exclude
    // the length of the null terminator.
    host = host.Substring(sizeof(kOriginWildcardPrefix) - 1);
  } else {
    scope_extension->has_origin_wildcard = false;
  }

  bool host_valid = IsHostValidForScopeExtension(host);
  if (!host_valid) {
    AddErrorInfo(
        "scope_extensions entry ignored, domain of required property 'origin' "
        "is invalid.");
    return std::nullopt;
  }

  if (scope_extension->has_origin_wildcard) {
    origin = SecurityOrigin::CreateFromValidTuple(origin->Protocol(), host,
                                                  origin->Port());
    if (!origin) {
      AddErrorInfo(
          "scope_extensions entry ignored, required property 'origin' is "
          "invalid.");
      return std::nullopt;
    }
  }

  scope_extension->origin = origin;
  return std::move(scope_extension);
}

KURL ManifestParser::ParseLockScreenStartUrl(const JSONObject* lock_screen) {
  if (!lock_screen->Get("start_url")) {
    return KURL();
  }
  KURL start_url = ParseURL(lock_screen, "start_url", manifest_url_,
                            ParseURLRestrictions::kWithinScope);
  if (!start_url.IsValid()) {
    // Error already reported by ParseURL.
    return KURL();
  }

  return start_url;
}

mojom::blink::ManifestLockScreenPtr ManifestParser::ParseLockScreen(
    const JSONObject* manifest) {
  if (!manifest->Get("lock_screen")) {
    return nullptr;
  }

  const JSONObject* lock_screen_object = manifest->GetJSONObject("lock_screen");
  if (!lock_screen_object) {
    AddErrorInfo("property 'lock_screen' ignored, type object expected.");
    return nullptr;
  }
  auto lock_screen = mojom::blink::ManifestLockScreen::New();
  lock_screen->start_url = ParseLockScreenStartUrl(lock_screen_object);

  return lock_screen;
}

KURL ManifestParser::ParseNoteTakingNewNoteUrl(const JSONObject* note_taking) {
  if (!note_taking->Get("n
```