Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `net/base/mime_util.cc`. They are particularly interested in:

1. **Listing the functionalities:** What does this code do?
2. **Relationship with JavaScript:** Does it interact with JavaScript, and if so, how?
3. **Logical Reasoning (Input/Output):**  If there are logical steps, provide example inputs and outputs.
4. **Common Usage Errors:** What mistakes can users or programmers make when using this code?
5. **Debugging Context:** How does a user's action lead to this code being executed, aiding in debugging?
6. **Overall Functionality (Summary):** A concise summary of the code's purpose.

Let's break down the code to address each of these points.

**1. Listing the functionalities:**

The code defines a class `MimeUtil` and associated functions to handle MIME type related operations. Key functionalities include:

*   **Mapping file extensions to MIME types:**  `GetMimeTypeFromExtension`, `GetWellKnownMimeTypeFromExtension`. It uses both hardcoded mappings and platform-specific mappings.
*   **Mapping MIME types to preferred file extensions:** `GetPreferredExtensionForMimeType`. It prioritizes platform settings.
*   **Getting the MIME type of a file:** `GetMimeTypeFromFile`.
*   **Matching MIME types against patterns (including wildcards):** `MatchesMimeType`.
*   **Parsing MIME type strings:** `ParseMimeType`, `ParseMimeTypeWithoutParameter`. This involves separating the main type, subtype, and parameters.
*   **Validating top-level MIME types:** `IsValidTopLevelMimeType`.
*   **Generating MIME multipart boundaries:** `GenerateMimeMultipartBoundary`.
*   **Retrieving all known extensions for a given MIME type:** `GetExtensionsForMimeType`.

**2. Relationship with JavaScript:**

MIME types are crucial for web browsers to understand how to handle different types of resources loaded from the web. JavaScript often interacts with MIME types in several scenarios:

*   **Fetching resources:** When JavaScript uses `fetch()` or `XMLHttpRequest` to request resources, the server responds with a `Content-Type` header that specifies the MIME type. JavaScript uses this to process the response data correctly.
*   **Form submissions:** When a form is submitted, the `enctype` attribute of the `<form>` tag specifies how the data should be encoded, often involving MIME types.
*   **Creating data URLs:** JavaScript can create data URLs (e.g., for images) which include the MIME type.
*   **Handling file uploads:** When a user uploads a file through a `<input type="file">` element, JavaScript can access the file's MIME type.

**3. Logical Reasoning (Input/Output):**

Let's consider the `GetMimeTypeFromExtension` function.

*   **Input:** A file extension (e.g., `"jpg"`, `"pdf"`, `"js"`).
*   **Process:** The function looks up the extension in its internal mappings (`kPrimaryMappings`, platform mappings, `kSecondaryMappings`). The order of lookup matters.
*   **Output:** The corresponding MIME type (e.g., `"image/jpeg"`, `"application/pdf"`, `"text/javascript"`).

Example:

*   **Input:** `"png"`
*   **Lookup:** Found in `kPrimaryMappings` as associated with `"image/png"`.
*   **Output:** `"image/png"`

*   **Input:** `"txt"`
*   **Lookup:** Not found in `kPrimaryMappings`. Platform mapping might exist. Found in `kSecondaryMappings` as associated with `"text/plain"`.
*   **Output:** `"text/plain"`

**4. Common Usage Errors:**

*   **Incorrect or missing file extensions:** If a URL or local file path doesn't have the correct extension, the MIME type detection might fail or return an incorrect type (e.g., `application/octet-stream`).
*   **Assuming a specific extension always maps to the same MIME type:** While generally true for common types, there can be exceptions or platform-specific differences. Relying on a hardcoded mapping in your own code might lead to issues.
*   **Case sensitivity of extensions:** While the code uses case-insensitive comparisons for extensions, it's good practice to be consistent with case.
*   **Not handling the `application/octet-stream` case:** When a server sends this MIME type, it means the content is opaque, and the browser shouldn't assume its type. Developers need to handle this appropriately.
*   **Incorrectly parsing MIME type strings:** Manually parsing MIME type strings without using robust libraries can lead to errors, especially when dealing with parameters and quoted values.

**5. Debugging Context:**

Imagine a user tries to open a `.webp` image in a Chromium browser. Here's how the execution might reach `mime_util.cc`:

1. **User Action:** The user clicks on a link to a `.webp` image, or a web page tries to display a `.webp` image.
2. **Network Request:** The browser makes a network request for the image.
3. **Response Headers:** The server responds with the image data and a `Content-Type` header, likely `image/webp`.
4. **MIME Type Check (Optional):**  Before even downloading, the browser might check if it knows how to handle `image/webp`.
5. **Determining How to Handle the Response:** The browser needs to determine how to render or process the received data. It might use the file extension from the URL (if available) or the `Content-Type` header.
6. **`GetMimeTypeFromExtension` Call:** If relying on the URL's extension, the browser (or some internal component) might call `GetMimeTypeFromExtension("webp", ...)` to get the associated MIME type.
7. **Processing Based on MIME Type:**  Based on the identified MIME type (`image/webp`), the browser loads the appropriate image decoder to render the image.

During debugging, if a `.webp` image isn't displaying correctly:

*   Check the server's `Content-Type` header in the network inspector. Is it correct?
*   If the URL doesn't have the `.webp` extension, the browser might not be able to determine the type correctly.
*   Stepping through the code, a developer could see the `GetMimeTypeFromExtension` function being called and verify that it correctly returns `image/webp`. If not, there might be an issue with the mappings.

**6. Overall Functionality (Summary):**

The `net/base/mime_util.cc` file provides core functionality within Chromium's networking stack for handling MIME types. It allows the browser to determine the type of a resource based on its file extension or MIME type string, enabling it to process and render web content correctly. It manages mappings between extensions and MIME types, supporting both standard types and platform-specific variations.

Now, let's structure the answer according to the user's request.
## 功能列表 - net/base/mime_util.cc (第 1 部分)

这个 C++ 文件 `net/base/mime_util.cc` 在 Chromium 的网络栈中扮演着处理 MIME 类型的重要角色。它提供了一系列功能，用于确定、比较和解析 MIME 类型，以及管理文件扩展名和 MIME 类型之间的映射关系。

具体功能包括：

1. **从文件扩展名获取 MIME 类型:**
    *   `GetMimeTypeFromExtension`:  根据给定的文件扩展名，查找并返回对应的 MIME 类型。它会考虑硬编码的映射关系以及平台相关的映射关系。
    *   `GetWellKnownMimeTypeFromExtension`:  类似于 `GetMimeTypeFromExtension`，但仅考虑硬编码的映射关系，忽略平台相关的映射。

2. **从 MIME 类型获取首选文件扩展名:**
    *   `GetPreferredExtensionForMimeType`: 根据给定的 MIME 类型，查找并返回其首选的文件扩展名。它会优先考虑平台设置。

3. **从文件路径获取 MIME 类型:**
    *   `GetMimeTypeFromFile`:  根据给定的文件路径，提取其扩展名，并使用 `GetMimeTypeFromExtension` 获取 MIME 类型。

4. **匹配 MIME 类型:**
    *   `MatchesMimeType`:  判断一个给定的 MIME 类型是否匹配一个模式。该模式可以包含通配符（`*`）。

5. **解析 MIME 类型字符串:**
    *   `ParseMimeType`:  解析一个完整的 MIME 类型字符串，将其分解为主要类型、子类型和参数。
    *   `ParseMimeTypeWithoutParameter`:  解析 MIME 类型字符串，提取主要类型和子类型，忽略参数。

6. **验证顶级 MIME 类型:**
    *   `IsValidTopLevelMimeType`:  检查给定的字符串是否为合法的顶级 MIME 类型。

7. **获取所有已知的文件扩展名:**
    *   `GetExtensionsForMimeType`:  根据给定的 MIME 类型，返回所有已知的与之关联的文件扩展名列表。

8. **生成 MIME 多部分边界:**
    *   `GenerateMimeMultipartBoundary`:  生成用于 MIME 多部分消息的随机边界字符串。

## 与 Javascript 的关系及举例说明

MIME 类型是 Web 浏览器理解如何处理服务器返回的资源的关键。JavaScript 在与网络交互时会涉及到 MIME 类型。`net/base/mime_util.cc` 的功能直接支持浏览器处理 JavaScript 相关资源：

**举例说明:**

1. **加载 JavaScript 文件 (`<script src="...">`)**:
    *   **用户操作:** 用户在浏览器中访问一个包含 `<script src="script.js"></script>` 的 HTML 页面。
    *   **浏览器行为:** 浏览器发起对 `script.js` 的网络请求。
    *   **服务器响应:** 服务器返回 `script.js` 的内容，并在 `Content-Type` 头部设置 MIME 类型为 `text/javascript` 或 `application/javascript`。
    *   **`mime_util.cc` 的作用:** 当浏览器接收到响应头部时，可能会调用 `ParseMimeType` 或 `ParseMimeTypeWithoutParameter` 来解析 `Content-Type` 的值，确认资源类型是 JavaScript。这确保了浏览器使用 JavaScript 引擎来执行该文件。

2. **处理 JavaScript 生成的数据 URL:**
    *   **JavaScript 代码:**  JavaScript 可以使用 `URL.createObjectURL()` 创建包含数据的 URL，例如 `data:image/png;base64,iVBORw0KGgo...`。
    *   **浏览器行为:** 当浏览器遇到这样的 URL 时，需要识别数据类型。
    *   **`mime_util.cc` 的作用:** 浏览器会解析数据 URL 中的 MIME 类型部分 (`image/png`)，这可能会涉及到 `ParseMimeTypeWithoutParameter` 的调用。根据解析出的 MIME 类型，浏览器知道如何处理这部分数据，例如将其渲染为图片。

3. **处理 Fetch API 的响应:**
    *   **JavaScript 代码:**  JavaScript 使用 `fetch()` API 发起网络请求。
    *   **服务器响应:** 服务器返回数据，并设置 `Content-Type` 头部。
    *   **JavaScript 处理:** JavaScript 可以通过 `response.blob()` 或 `response.json()` 等方法来处理响应数据。浏览器会根据 `Content-Type` 头部来辅助这些处理。
    *   **`mime_util.cc` 的作用:**  在判断如何处理响应体时，浏览器会使用 `mime_util.cc` 中的函数（如 `MatchesMimeType`）来判断 `Content-Type` 是否匹配预期的类型（例如，判断 `Content-Type` 是否为 `application/json` 以决定是否调用 JSON 解析器）。

## 逻辑推理 (假设输入与输出)

**假设输入与输出示例:**

**1. `GetMimeTypeFromExtension`:**

*   **假设输入:**  `.jpg`
*   **逻辑推理:** 函数首先在 `kPrimaryMappings` 中查找，找到 `{"image/jpeg", "jpeg,jpg"}`，其中包含 `jpg`。
*   **假设输出:** `image/jpeg`

*   **假设输入:** `.unknown`
*   **逻辑推理:** 函数在 `kPrimaryMappings` 和 `kSecondaryMappings` 中都找不到该扩展名，然后会尝试平台相关的映射。假设平台没有该映射。
*   **假设输出:**  可能为空字符串或根据平台行为返回一个默认的 MIME 类型（例如 `application/octet-stream`，但代码中并没有直接返回这个，需要看平台实现）。

**2. `GetPreferredExtensionForMimeType`:**

*   **假设输入:** `text/html`
*   **逻辑推理:** 函数首先检查平台是否有偏好。如果没有，则在 `kPrimaryMappings` 中找到 `{"text/html", "html,htm,shtml,shtm"}`，首选扩展名为 `html`。
*   **假设输出:**  `html` (在 Windows 上可能是 `html` 的 `wstring` 表示)

**3. `MatchesMimeType`:**

*   **假设输入:** `mime_type_pattern = "image/*"`, `mime_type = "image/png"`
*   **逻辑推理:**  模式中的 `*` 匹配 `png`。
*   **假设输出:** `true`

*   **假设输入:** `mime_type_pattern = "text/html; charset=utf-8"`, `mime_type = "text/html"`
*   **逻辑推理:**  模式中存在参数 `charset=utf-8`，但被测试的 MIME 类型中没有该参数。
*   **假设输出:** `false`

## 用户或编程常见的使用错误

1. **假设文件扩展名总是存在且正确:** 开发者可能假设所有需要确定 MIME 类型的文件都有正确的扩展名，但实际情况并非总是如此。例如，服务器配置错误可能导致下载的文件没有扩展名。
    *   **示例:** 下载一个文件时，服务器没有设置 `Content-Disposition` 头部或者设置不当，导致浏览器无法获取文件名和扩展名。这时调用依赖文件扩展名的函数会失败或返回不准确的结果.

2. **忽略 `application/octet-stream`:** 当服务器返回 `application/octet-stream` 时，意味着服务器没有指明资源的具体类型。开发者不应该在这种情况下盲目猜测文件类型并进行处理。
    *   **示例:**  一个 API 返回二进制数据，但 `Content-Type` 被错误地设置为 `application/octet-stream`。前端 JavaScript 如果简单地尝试将其解析为 JSON，将会失败。

3. **不正确的 MIME 类型匹配假设:**  开发者可能错误地使用字符串比较来匹配 MIME 类型，而忽略了大小写不敏感以及参数的存在。
    *   **示例:**  检查 `Content-Type` 是否为 `text/html` 时，直接使用 `===` 比较，而没有考虑 `text/html; charset=UTF-8` 这种情况。

4. **过度依赖硬编码的 MIME 类型映射:** 虽然 `mime_util.cc` 自身包含硬编码的映射，但过度依赖这些映射而忽略平台提供的更细致的映射可能导致在某些系统上出现问题。

## 用户操作如何一步步地到达这里 (调试线索)

以下是一些用户操作如何触发 `net/base/mime_util.cc` 中代码执行的场景，可以作为调试线索：

1. **用户访问一个网页 (加载资源):**
    *   **操作:** 用户在浏览器地址栏输入网址或点击一个链接。
    *   **浏览器行为:** 浏览器解析 HTML，发现需要加载各种资源 (图片、CSS、JavaScript、字体等)。
    *   **网络请求:** 浏览器为每个资源发起网络请求。
    *   **服务器响应:** 服务器返回资源内容以及 `Content-Type` 头部。
    *   **`mime_util.cc` 介入:** 浏览器接收到响应头部，需要确定如何处理资源。会调用 `ParseMimeType` 或 `ParseMimeTypeWithoutParameter` 解析 `Content-Type`，并可能调用 `GetMimeTypeFromExtension` (如果 URL 中包含扩展名) 或 `MatchesMimeType` (进行类型匹配)。

2. **用户下载文件:**
    *   **操作:** 用户点击一个下载链接。
    *   **浏览器行为:** 浏览器发起下载请求。
    *   **服务器响应:** 服务器返回文件内容以及可能包含 `Content-Type` 和 `Content-Disposition` 头部。
    *   **`mime_util.cc` 介入:** 浏览器需要确定文件的类型以进行处理（例如，决定是否直接显示、交给外部应用处理）。可能会调用 `GetMimeTypeFromExtension` (基于 URL 或 `Content-Disposition` 中提取的扩展名) 或直接解析 `Content-Type`。

3. **用户上传文件:**
    *   **操作:** 用户在网页上选择文件并通过表单上传。
    *   **浏览器行为:** 浏览器读取用户选择的文件，并根据表单的 `enctype` 属性构建请求体。
    *   **`mime_util.cc` 介入:**  在构建请求体时，浏览器可能需要确定上传文件的 MIME 类型，这会调用 `GetMimeTypeFromFile` 或 `GetMimeTypeFromExtension`。

4. **浏览器处理数据 URL:**
    *   **操作:** 网页 JavaScript 代码创建或使用了数据 URL。
    *   **浏览器行为:** 浏览器需要解析数据 URL 以确定数据的类型。
    *   **`mime_util.cc` 介入:** 浏览器会调用 `ParseMimeTypeWithoutParameter` 来解析数据 URL 中指定的 MIME 类型。

**调试线索:** 当遇到与 MIME 类型相关的问题时，可以：

*   **检查网络请求的头部:** 使用浏览器的开发者工具 (Network 标签) 查看资源的 `Content-Type` 头部是否正确。
*   **检查 URL 的扩展名:** 确保资源的 URL 包含正确的文件扩展名。
*   **断点调试:** 在 Chromium 源码中，在 `net/base/mime_util.cc` 的相关函数设置断点，查看调用栈和变量值，了解 MIME 类型是如何被解析和处理的。

## 归纳功能 (第 1 部分)

总而言之，`net/base/mime_util.cc` (第一部分) 的主要功能是提供了一套用于 **管理和处理 MIME 类型** 的核心工具。它允许 Chromium 根据文件扩展名、MIME 类型字符串等信息来 **识别资源类型**，并支持进行 **类型匹配** 和 **解析**。这些功能对于浏览器正确加载、渲染和处理各种网络资源至关重要，并直接影响到与 JavaScript 相关的 Web 功能的正常运作。它维护了硬编码的 MIME 类型映射，并允许集成平台相关的映射，以提供更全面和准确的 MIME 类型处理能力。

### 提示词
```
这是目录为net/base/mime_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/mime_util.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

#include "base/base64.h"
#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/lazy_instance.h"
#include "base/memory/raw_ptr_exclusion.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "net/base/platform_mime_util.h"
#include "net/http/http_util.h"

using std::string;

namespace net {

// Singleton utility class for mime types.
class MimeUtil : public PlatformMimeUtil {
 public:
  bool GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                std::string* mime_type) const;

  bool GetMimeTypeFromFile(const base::FilePath& file_path,
                           std::string* mime_type) const;

  bool GetWellKnownMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                         std::string* mime_type) const;

  bool GetPreferredExtensionForMimeType(
      std::string_view mime_type,
      base::FilePath::StringType* extension) const;

  bool MatchesMimeType(std::string_view mime_type_pattern,
                       std::string_view mime_type) const;

  bool ParseMimeTypeWithoutParameter(std::string_view type_string,
                                     std::string* top_level_type,
                                     std::string* subtype) const;

  bool IsValidTopLevelMimeType(std::string_view type_string) const;

 private:
  friend struct base::LazyInstanceTraitsBase<MimeUtil>;

  MimeUtil();

  bool GetMimeTypeFromExtensionHelper(const base::FilePath::StringType& ext,
                                      bool include_platform_types,
                                      std::string* mime_type) const;
};  // class MimeUtil

// This variable is Leaky because we need to access it from WorkerPool threads.
static base::LazyInstance<MimeUtil>::Leaky g_mime_util =
    LAZY_INSTANCE_INITIALIZER;

struct MimeInfo {
  const std::string_view mime_type;

  // Comma-separated list of possible extensions for the type. The first
  // extension is considered preferred.
  const std::string_view extensions;
};

// How to use the MIME maps
// ------------------------
// READ THIS BEFORE MODIFYING THE MIME MAPPINGS BELOW.
//
// There are two hardcoded mappings from MIME types: kPrimaryMappings and
// kSecondaryMappings.
//
// kPrimaryMappings:
//
//   Use this for mappings that are critical to the web platform.  Mappings you
//   add to this list take priority over the underlying platform when converting
//   from file extension -> MIME type.  Thus file extensions listed here will
//   work consistently across platforms.
//
// kSecondaryMappings:
//
//   Use this for mappings that must exist, but can be overridden by user
//   preferences.
//
// The following applies to both lists:
//
// * The same extension can appear multiple times in the same list under
//   different MIME types.  Extensions that appear earlier take precedence over
//   those that appear later.
//
// * A MIME type must not appear more than once in a single list.  It is valid
//   for the same MIME type to appear in kPrimaryMappings and
//   kSecondaryMappings.
//
// The MIME maps are used for three types of lookups:
//
// 1) MIME type -> file extension.  Implemented as
//    GetPreferredExtensionForMimeType().
//
//    Sources are consulted in the following order:
//
//    a) As a special case application/octet-stream is mapped to nothing.  Web
//       sites are supposed to use this MIME type to indicate that the content
//       is opaque and shouldn't be parsed as any specific type of content.  It
//       doesn't make sense to map this to anything.
//
//    b) The underlying platform.  If the operating system has a mapping from
//       the MIME type to a file extension, then that takes priority.  The
//       platform is assumed to represent the user's preference.
//
//    c) kPrimaryMappings.  Order doesn't matter since there should only be at
//       most one entry per MIME type.
//
//    d) kSecondaryMappings.  Again, order doesn't matter.
//
// 2) File extension -> MIME type.  Implemented in GetMimeTypeFromExtension().
//
//    Sources are considered in the following order:
//
//    a) kPrimaryMappings.  Order matters here since file extensions can appear
//       multiple times on these lists.  The first mapping in order of
//       appearance in the list wins.
//
//    b) Underlying platform.
//
//    c) kSecondaryMappings.  Again, the order matters.
//
// 3) File extension -> Well known MIME type.  Implemented as
//    GetWellKnownMimeTypeFromExtension().
//
//    This is similar to 2), with the exception that b) is skipped.  I.e.  Only
//    considers the hardcoded mappings in kPrimaryMappings and
//    kSecondaryMappings.

// See comments above for details on how this list is used.
static const MimeInfo kPrimaryMappings[] = {
    // Must precede audio/webm .
    {"video/webm", "webm"},

    // Must precede audio/mp3
    {"audio/mpeg", "mp3"},

    {"application/wasm", "wasm"},
    {"application/x-chrome-extension", "crx"},
    {"application/xhtml+xml", "xhtml,xht,xhtm"},
    {"audio/flac", "flac"},
    {"audio/mp3", "mp3"},
    {"audio/ogg", "ogg,oga,opus"},
    {"audio/wav", "wav"},
    {"audio/webm", "webm"},
    {"audio/x-m4a", "m4a"},
    {"image/avif", "avif"},
    {"image/gif", "gif"},
    {"image/jpeg", "jpeg,jpg"},
    {"image/png", "png"},
    {"image/apng", "png,apng"},
    {"image/svg+xml", "svg,svgz"},
    {"image/webp", "webp"},
    {"multipart/related", "mht,mhtml"},
    {"text/css", "css"},
    {"text/html", "html,htm,shtml,shtm"},
    {"text/javascript", "js,mjs"},
    {"text/xml", "xml"},
    {"video/mp4", "mp4,m4v"},
    {"video/ogg", "ogv,ogm"},

    // This is a primary mapping (overrides the platform) rather than secondary
    // to work around an issue when Excel is installed on Windows. Excel
    // registers csv as application/vnd.ms-excel instead of text/csv from RFC
    // 4180. See https://crbug.com/139105.
    {"text/csv", "csv"},
};

// See comments above for details on how this list is used.
static const MimeInfo kSecondaryMappings[] = {
    // Must precede image/vnd.microsoft.icon .
    {"image/x-icon", "ico"},

    {"application/epub+zip", "epub"},
    {"application/font-woff", "woff"},
    {"application/gzip", "gz,tgz"},
    {"application/javascript", "js"},
    {"application/json", "json"},  // Per http://www.ietf.org/rfc/rfc4627.txt.
    {"application/msword", "doc,dot"},
    {"application/octet-stream", "bin,exe,com"},
    {"application/pdf", "pdf"},
    {"application/pkcs7-mime", "p7m,p7c,p7z"},
    {"application/pkcs7-signature", "p7s"},
    {"application/postscript", "ps,eps,ai"},
    {"application/rdf+xml", "rdf"},
    {"application/rss+xml", "rss"},
    {"application/rtf", "rtf"},
    {"application/vnd.android.package-archive", "apk"},
    {"application/vnd.mozilla.xul+xml", "xul"},
    {"application/vnd.ms-excel", "xls"},
    {"application/vnd.ms-powerpoint", "ppt"},
    {"application/"
     "vnd.openxmlformats-officedocument.presentationml.presentation",
     "pptx"},
    {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     "xlsx"},
    {"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "docx"},
    {"application/x-gzip", "gz,tgz"},
    {"application/x-mpegurl", "m3u8"},
    {"application/x-shockwave-flash", "swf,swl"},
    {"application/x-tar", "tar"},
    {"application/x-x509-ca-cert", "cer,crt"},
    {"application/zip", "zip"},
    // This is the platform mapping on recent versions of Windows 10.
    {"audio/webm", "weba"},
    {"image/bmp", "bmp"},
    {"image/jpeg", "jfif,pjpeg,pjp"},
    {"image/tiff", "tiff,tif"},
    {"image/vnd.microsoft.icon", "ico"},
    {"image/x-png", "png"},
    {"image/x-xbitmap", "xbm"},
    {"message/rfc822", "eml"},
    {"text/calendar", "ics"},
    {"text/html", "ehtml"},
    {"text/plain", "txt,text"},
    {"text/vtt", "vtt"},
    {"text/x-sh", "sh"},
    {"text/xml", "xsl,xbl,xslt"},
    {"video/mpeg", "mpeg,mpg"},
};

// Finds mime type of |ext| from |mappings|.
template <size_t num_mappings>
static std::optional<std::string_view> FindMimeType(
    const MimeInfo (&mappings)[num_mappings],
    const std::string& ext) {
  for (const auto& mapping : mappings) {
    for (std::string_view extension :
         base::SplitStringPiece(mapping.extensions, ",", base::TRIM_WHITESPACE,
                                base::SPLIT_WANT_ALL)) {
      if (base::EqualsCaseInsensitiveASCII(extension, ext)) {
        return mapping.mime_type;
      }
    }
  }
  return std::nullopt;
}

static base::FilePath::StringType StringToFilePathStringType(
    std::string_view string_piece) {
#if BUILDFLAG(IS_WIN)
  return base::UTF8ToWide(string_piece);
#else
  return std::string(string_piece);
#endif
}

// Helper used in MimeUtil::GetPreferredExtensionForMimeType() to search
// preferred extension in MimeInfo arrays.
template <size_t num_mappings>
static bool FindPreferredExtension(const MimeInfo (&mappings)[num_mappings],
                                   std::string_view mime_type,
                                   base::FilePath::StringType* result) {
  // There is no preferred extension for "application/octet-stream".
  if (mime_type == "application/octet-stream")
    return false;

  for (const auto& mapping : mappings) {
    if (mapping.mime_type == mime_type) {
      const size_t pos = mapping.extensions.find(',');
      *result = StringToFilePathStringType(mapping.extensions.substr(0, pos));
      return true;
    }
  }
  return false;
}

bool MimeUtil::GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                        string* result) const {
  return GetMimeTypeFromExtensionHelper(ext, true, result);
}

bool MimeUtil::GetWellKnownMimeTypeFromExtension(
    const base::FilePath::StringType& ext,
    string* result) const {
  return GetMimeTypeFromExtensionHelper(ext, false, result);
}

bool MimeUtil::GetPreferredExtensionForMimeType(
    std::string_view mime_type,
    base::FilePath::StringType* extension) const {
  // Search the MIME type in the platform DB first, then in kPrimaryMappings and
  // kSecondaryMappings.
  return GetPlatformPreferredExtensionForMimeType(mime_type, extension) ||
         FindPreferredExtension(kPrimaryMappings, mime_type, extension) ||
         FindPreferredExtension(kSecondaryMappings, mime_type, extension);
}

bool MimeUtil::GetMimeTypeFromFile(const base::FilePath& file_path,
                                   string* result) const {
  base::FilePath::StringType file_name_str = file_path.Extension();
  if (file_name_str.empty())
    return false;
  return GetMimeTypeFromExtension(file_name_str.substr(1), result);
}

bool MimeUtil::GetMimeTypeFromExtensionHelper(
    const base::FilePath::StringType& ext,
    bool include_platform_types,
    string* result) const {
  DCHECK(ext.empty() || ext[0] != '.')
      << "extension passed in must not include leading dot";

  // Avoids crash when unable to handle a long file path. See crbug.com/48733.
  const unsigned kMaxFilePathSize = 65536;
  if (ext.length() > kMaxFilePathSize)
    return false;

  // Reject a string which contains null character.
  base::FilePath::StringType::size_type nul_pos =
      ext.find(FILE_PATH_LITERAL('\0'));
  if (nul_pos != base::FilePath::StringType::npos)
    return false;

  // We implement the same algorithm as Mozilla for mapping a file extension to
  // a mime type.  That is, we first check a hard-coded list (that cannot be
  // overridden), and then if not found there, we defer to the system registry.
  // Finally, we scan a secondary hard-coded list to catch types that we can
  // deduce but that we also want to allow the OS to override.

  base::FilePath path_ext(ext);
  const string ext_narrow_str = path_ext.AsUTF8Unsafe();
  std::optional<std::string_view> mime_type =
      FindMimeType(kPrimaryMappings, ext_narrow_str);
  if (mime_type) {
    *result = mime_type.value();
    return true;
  }

  if (include_platform_types && GetPlatformMimeTypeFromExtension(ext, result))
    return true;

  mime_type = FindMimeType(kSecondaryMappings, ext_narrow_str);
  if (mime_type) {
    *result = mime_type.value();
    return true;
  }

  return false;
}

MimeUtil::MimeUtil() = default;

// Tests for MIME parameter equality. Each parameter in the |mime_type_pattern|
// must be matched by a parameter in the |mime_type|. If there are no
// parameters in the pattern, the match is a success.
//
// According rfc2045 keys of parameters are case-insensitive, while values may
// or may not be case-sensitive, but they are usually case-sensitive. So, this
// function matches values in *case-sensitive* manner, however note that this
// may produce some false negatives.
bool MatchesMimeTypeParameters(std::string_view mime_type_pattern,
                               std::string_view mime_type) {
  typedef std::map<std::string, std::string> StringPairMap;

  const std::string_view::size_type semicolon = mime_type_pattern.find(';');
  const std::string_view::size_type test_semicolon = mime_type.find(';');
  if (semicolon != std::string::npos) {
    if (test_semicolon == std::string::npos)
      return false;

    base::StringPairs pattern_parameters;
    base::SplitStringIntoKeyValuePairs(mime_type_pattern.substr(semicolon + 1),
                                       '=', ';', &pattern_parameters);
    base::StringPairs test_parameters;
    base::SplitStringIntoKeyValuePairs(mime_type.substr(test_semicolon + 1),
                                       '=', ';', &test_parameters);

    // Put the parameters to maps with the keys converted to lower case.
    StringPairMap pattern_parameter_map;
    for (const auto& pair : pattern_parameters) {
      pattern_parameter_map[base::ToLowerASCII(pair.first)] = pair.second;
    }

    StringPairMap test_parameter_map;
    for (const auto& pair : test_parameters) {
      test_parameter_map[base::ToLowerASCII(pair.first)] = pair.second;
    }

    if (pattern_parameter_map.size() > test_parameter_map.size())
      return false;

    for (const auto& parameter_pair : pattern_parameter_map) {
      const auto& test_parameter_pair_it =
          test_parameter_map.find(parameter_pair.first);
      if (test_parameter_pair_it == test_parameter_map.end())
        return false;
      if (parameter_pair.second != test_parameter_pair_it->second)
        return false;
    }
  }

  return true;
}

// This comparison handles absolute maching and also basic
// wildcards.  The plugin mime types could be:
//      application/x-foo
//      application/*
//      application/*+xml
//      *
// Also tests mime parameters -- all parameters in the pattern must be present
// in the tested type for a match to succeed.
bool MimeUtil::MatchesMimeType(std::string_view mime_type_pattern,
                               std::string_view mime_type) const {
  if (mime_type_pattern.empty())
    return false;

  std::string_view::size_type semicolon = mime_type_pattern.find(';');
  const std::string_view base_pattern = mime_type_pattern.substr(0, semicolon);
  semicolon = mime_type.find(';');
  const std::string_view base_type = mime_type.substr(0, semicolon);

  if (base_pattern == "*" || base_pattern == "*/*")
    return MatchesMimeTypeParameters(mime_type_pattern, mime_type);

  const std::string_view::size_type star = base_pattern.find('*');
  if (star == std::string::npos) {
    if (base::EqualsCaseInsensitiveASCII(base_pattern, base_type))
      return MatchesMimeTypeParameters(mime_type_pattern, mime_type);
    else
      return false;
  }

  // Test length to prevent overlap between |left| and |right|.
  if (base_type.length() < base_pattern.length() - 1)
    return false;

  std::string_view base_pattern_piece(base_pattern);
  std::string_view left(base_pattern_piece.substr(0, star));
  std::string_view right(base_pattern_piece.substr(star + 1));

  if (!base::StartsWith(base_type, left, base::CompareCase::INSENSITIVE_ASCII))
    return false;

  if (!right.empty() &&
      !base::EndsWith(base_type, right, base::CompareCase::INSENSITIVE_ASCII))
    return false;

  return MatchesMimeTypeParameters(mime_type_pattern, mime_type);
}

bool ParseMimeType(std::string_view type_str,
                   std::string* mime_type,
                   base::StringPairs* params) {
  // Trim leading and trailing whitespace from type.  We include '(' in
  // the trailing trim set to catch media-type comments, which are not at all
  // standard, but may occur in rare cases.
  size_t type_val = type_str.find_first_not_of(HTTP_LWS);
  type_val = std::min(type_val, type_str.length());
  size_t type_end = type_str.find_first_of(HTTP_LWS ";(", type_val);
  if (type_end == std::string::npos)
    type_end = type_str.length();

  // Reject a mime-type if it does not include a slash.
  size_t slash_pos = type_str.find_first_of('/');
  if (slash_pos == std::string::npos || slash_pos > type_end)
    return false;
  if (mime_type)
    *mime_type = type_str.substr(type_val, type_end - type_val);

  // Iterate over parameters. Can't split the string around semicolons
  // preemptively because quoted strings may include semicolons. Mostly matches
  // logic in https://mimesniff.spec.whatwg.org/. Main differences: Does not
  // validate characters are HTTP token code points / HTTP quoted-string token
  // code points, and ignores spaces after "=" in parameters.
  if (params)
    params->clear();
  std::string::size_type offset = type_str.find_first_of(';', type_end);
  while (offset < type_str.size()) {
    DCHECK_EQ(';', type_str[offset]);
    // Trim off the semicolon.
    ++offset;

    // Trim off any following spaces.
    offset = type_str.find_first_not_of(HTTP_LWS, offset);
    std::string::size_type param_name_start = offset;

    // Extend parameter name until run into a semicolon or equals sign.  Per
    // spec, trailing spaces are not removed.
    offset = type_str.find_first_of(";=", offset);

    // Nothing more to do if at end of string, or if there's no parameter
    // value, since names without values aren't allowed.
    if (offset == std::string::npos || type_str[offset] == ';')
      continue;

    auto param_name = base::MakeStringPiece(type_str.begin() + param_name_start,
                                            type_str.begin() + offset);

    // Now parse the value.
    DCHECK_EQ('=', type_str[offset]);
    // Trim off the '='.
    offset++;

    // Remove leading spaces. This violates the spec, though it matches
    // pre-existing behavior.
    //
    // TODO(mmenke): Consider doing this (only?) after parsing quotes, which
    // seems to align more with the spec - not the content-type spec, but the
    // GET spec's way of getting an encoding, and the spec for handling
    // boundary values as well.
    // See https://encoding.spec.whatwg.org/#names-and-labels.
    offset = type_str.find_first_not_of(HTTP_LWS, offset);

    std::string param_value;
    if (offset == std::string::npos || type_str[offset] == ';') {
      // Nothing to do here - an unquoted string of only whitespace should be
      // skipped.
      continue;
    } else if (type_str[offset] != '"') {
      // If the first character is not a quotation mark, copy data directly.
      std::string::size_type value_start = offset;
      offset = type_str.find_first_of(';', offset);
      std::string::size_type value_end = offset;

      // Remove terminal whitespace. If ran off the end of the string, have to
      // update |value_end| first.
      if (value_end == std::string::npos)
        value_end = type_str.size();
      while (value_end > value_start &&
             HttpUtil::IsLWS(type_str[value_end - 1])) {
        --value_end;
      }

      param_value = type_str.substr(value_start, value_end - value_start);
    } else {
      // Otherwise, append data, with special handling for backslashes, until
      // a close quote.  Do not trim whitespace for quoted-string.

      // Skip open quote.
      DCHECK_EQ('"', type_str[offset]);
      ++offset;

      while (offset < type_str.size() && type_str[offset] != '"') {
        // Skip over backslash and append the next character, when not at
        // the end of the string. Otherwise, copy the next character (Which may
        // be a backslash).
        if (type_str[offset] == '\\' && offset + 1 < type_str.size()) {
          ++offset;
        }
        param_value += type_str[offset];
        ++offset;
      }

      offset = type_str.find_first_of(';', offset);
    }
    if (params)
      params->emplace_back(param_name, param_value);
  }
  return true;
}

bool MimeUtil::ParseMimeTypeWithoutParameter(std::string_view type_string,
                                             std::string* top_level_type,
                                             std::string* subtype) const {
  std::vector<std::string_view> components = base::SplitStringPiece(
      type_string, "/", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (components.size() != 2)
    return false;
  components[0] = TrimWhitespaceASCII(components[0], base::TRIM_LEADING);
  components[1] = TrimWhitespaceASCII(components[1], base::TRIM_TRAILING);
  if (!HttpUtil::IsToken(components[0]) || !HttpUtil::IsToken(components[1]))
    return false;

  if (top_level_type)
    top_level_type->assign(std::string(components[0]));

  if (subtype)
    subtype->assign(std::string(components[1]));

  return true;
}

// See https://www.iana.org/assignments/media-types/media-types.xhtml
static const char* const kLegalTopLevelTypes[] = {
    "application", "audio", "example",   "font", "image",
    "message",     "model", "multipart", "text", "video",
};

bool MimeUtil::IsValidTopLevelMimeType(std::string_view type_string) const {
  std::string lower_type = base::ToLowerASCII(type_string);
  for (const char* const legal_type : kLegalTopLevelTypes) {
    if (lower_type.compare(legal_type) == 0) {
      return true;
    }
  }

  return type_string.size() > 2 &&
         base::StartsWith(type_string, "x-",
                          base::CompareCase::INSENSITIVE_ASCII);
}

//----------------------------------------------------------------------------
// Wrappers for the singleton
//----------------------------------------------------------------------------

bool GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                              std::string* mime_type) {
  return g_mime_util.Get().GetMimeTypeFromExtension(ext, mime_type);
}

bool GetMimeTypeFromFile(const base::FilePath& file_path,
                         std::string* mime_type) {
  return g_mime_util.Get().GetMimeTypeFromFile(file_path, mime_type);
}

bool GetWellKnownMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                       std::string* mime_type) {
  return g_mime_util.Get().GetWellKnownMimeTypeFromExtension(ext, mime_type);
}

bool GetPreferredExtensionForMimeType(std::string_view mime_type,
                                      base::FilePath::StringType* extension) {
  return g_mime_util.Get().GetPreferredExtensionForMimeType(mime_type,
                                                            extension);
}

bool MatchesMimeType(std::string_view mime_type_pattern,
                     std::string_view mime_type) {
  return g_mime_util.Get().MatchesMimeType(mime_type_pattern, mime_type);
}

bool ParseMimeTypeWithoutParameter(std::string_view type_string,
                                   std::string* top_level_type,
                                   std::string* subtype) {
  return g_mime_util.Get().ParseMimeTypeWithoutParameter(
      type_string, top_level_type, subtype);
}

bool IsValidTopLevelMimeType(std::string_view type_string) {
  return g_mime_util.Get().IsValidTopLevelMimeType(type_string);
}

namespace {

// From http://www.w3schools.com/media/media_mimeref.asp and
// http://plugindoc.mozdev.org/winmime.php
static const char* const kStandardImageTypes[] = {"image/avif",
                                                  "image/bmp",
                                                  "image/cis-cod",
                                                  "image/gif",
                                                  "image/heic",
                                                  "image/heif",
                                                  "image/ief",
                                                  "image/jpeg",
                                                  "image/webp",
                                                  "image/pict",
                                                  "image/pipeg",
                                                  "image/png",
                                                  "image/svg+xml",
                                                  "image/tiff",
                                                  "image/vnd.microsoft.icon",
                                                  "image/x-cmu-raster",
                                                  "image/x-cmx",
                                                  "image/x-icon",
                                                  "image/x-portable-anymap",
                                                  "image/x-portable-bitmap",
                                                  "image/x-portable-graymap",
                                                  "image/x-portable-pixmap",
                                                  "image/x-rgb",
                                                  "image/x-xbitmap",
                                                  "image/x-xpixmap",
                                                  "image/x-xwindowdump"};
static const char* const kStandardAudioTypes[] = {
  "audio/aac",
  "audio/aiff",
  "audio/amr",
  "audio/basic",
  "audio/flac",
  "audio/midi",
  "audio/mp3",
  "audio/mp4",
  "audio/mpeg",
  "audio/mpeg3",
  "audio/ogg",
  "audio/vorbis",
  "audio/wav",
  "audio/webm",
  "audio/x-m4a",
  "audio/x-ms-wma",
  "audio/vnd.rn-realaudio",
  "audio/vnd.wave"
};
// https://tools.ietf.org/html/rfc8081
static const char* const kStandardFontTypes[] = {
    "font/collection", "font/otf",  "font/sfnt",
    "font/ttf",        "font/woff", "font/woff2",
};
static const char* const kStandardVideoTypes[] = {
  "video/avi",
  "video/divx",
  "video/flc",
  "video/mp4",
  "video/mpeg",
  "video/ogg",
  "video/quicktime",
  "video/sd-video",
  "video/webm",
  "video/x-dv",
  "video/x-m4v",
  "video/x-mpeg",
  "video/x-ms-asf",
  "video/x-ms-wmv"
};

struct StandardType {
  const char* const leading_mime_type;
  // TODO(367764863) Rewrite to base::raw_span.
  RAW_PTR_EXCLUSION base::span<const char* const> standard_types;
};
static const StandardType kStandardTypes[] = {{"image/", kStandardImageTypes},
                                              {"audio/", kStandardAudioTypes},
                                              {"font/", kStandardFontTypes},
                                              {"video/", kStandardVideoTypes},
                                              {nullptr, {}}};

// GetExtensionsFromHardCodedMappings() adds file extensions (without a leading
// dot) to the set |extensions|, for all MIME types matching |mime_type|.
//
// The meaning of |mime_type| depends on the value of |prefix_match|:
//
//  * If |prefix_match = false| then |mime_type| is an exact (case-insensitive)
//    string such as "text/plain".
//
//  * If |prefix_match = true| then |mime_type| is treated as the prefix for a
//    (case-insensitive) string. For instance "Text/" would match "text/plain".
void GetExtensionsFromHardCodedMappings(
    base::span<const MimeInfo> mappings,
    const std::string& mime_type,
    bool prefix_match,
    std::unordered_set<base::FilePath::StringType>* extensions) {
  for (const auto& mapping : mappings) {
    std::string_view cur_mime_type(mapping.mime_type);

    if (base::StartsWith(cur_mime_type, mime_type,
                         base::CompareCase::INSENSITIVE_ASCII) &&
        (prefix_match || (cur_mime_type.length() == mime_type.length()))) {
      for (std::string_view this_extension : base::SplitStringPiece(
               mapping.extensions, ",", base::TRIM_WHITESPACE,
               base::SPLIT_WANT_ALL)) {
        extensions->insert(StringToFilePathStringType(this_extension));
      }
    }
  }
}

void GetExtensionsHelper(
    base::span<const char* const> standard_types,
    const std::string& leading_mime_type,
    std::unordered_set<base::FilePath::StringType>* extensions) {
  for (auto* standard_type : standard_types) {
    g_mime_util.Get().GetPlatformExtensionsForMimeType(standard_type,
                                                       extensions);
  }

  // Also look up the extensions from hard-coded mappings in case that some
  // supported extensions are not registered in the system registry, like ogg.
  GetExtensionsFromHardCodedMappings(kPrimaryMappings, leading_mime_type, true,
                                     extensions);

  GetExtensionsFromHardCodedMappings(kSecondaryMappings, leading_mime_type,
                                     true, extensions);
}

// Note that the elements in the source set will be appended to the target
// vector.
template <class T>
void UnorderedSetToVector(std::unordered_set<T>* source,
                          std::vector<T>* target) {
  size_t old_target_size = target->size();
  target->resize(old_target_size + source->size());
  size_t i = 0;
  for (auto iter = source->begin(); iter != source->end(); ++iter, ++i)
    (*target)[old_target_size + i] = *iter;
}

// Characters to be used for mime multipart boundary.
//
// TODO(rsleevi): crbug.com/575779: Follow the spec or fix the spec.
// The RFC 2046 spec says the alphanumeric characters plus the
// following characters are legal for boundaries:  '()+_,-./:=?
// However the following characters, though legal, cause some sites
// to fail: (),./:=+
constexpr std::string_view kMimeBoundaryCharacters(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

// Size of mime multipart boundary.
const size_t kMimeBoundarySize = 69;

}  // namespace

void GetExtensionsForMimeType(
    std::string_view unsafe_mime_type,
    std::vector<base::FilePath::StringType>* extensions) {
  if (unsafe_mime_type == "*/*" || unsafe_mime_type == "*")
    return;

  const std::string mime_type = base::ToLowerASCII(unsafe_mime_type);
  std::unordered_set<base::FilePath::StringType> unique_extensions;

  if (base::EndsWith(mime_type, "/*", base::CompareCase::INSENSITIVE_ASCII)) {
    std::string leading_mime_type = mime_type.substr(0, mime_type.length() - 1);

    // Find the matching StandardType from within kStandardTypes, or fall
    // through to the last (default) StandardType.
    const StandardType* type = nullptr;
    for (const StandardType& standard_type : kStandardTypes) {
      type = &standard_type;
      if (type->leading_mime_type &&
          leading_mime_type == type->leading_mime_type) {
        break;
      }
    }
    DCHECK(type);
    GetExtensionsHelper(type->standard_types,
                        leading_mime_type,
                        &unique_extensions);
  } else {
    g_mime_util.Get().GetPlatformExtensionsForMimeType(mime_type,
                                                       &unique_extensions);

    // Also look up the extensions from hard-coded mappings in case that some
    // supported extensions are not registered in the system registry, like ogg.
    GetExtensionsFromHardCodedMappings(kPrimaryMappings, mime_type, false,
                                       &unique_extensions);

    GetExtensionsFromHardCodedMappings(kSecondaryMappings, mime_type, false,
                                       &unique_extensions);
  }

  UnorderedSetToVector(&unique_extensions, extensions);
}

NET_EXPORT std::string GenerateMimeMultipartBoundary() {
  // Based on RFC 1341, section "7.2.1 Multipart: The common syntax":
  //   Because encapsulation boundaries must not appear in the body parts being
  //   encapsulated, a user agent must exercise care to choose a unique
  //   boundary. The boundary in the example above could have been the result of
  //   an algorithm designed to produce boundaries with a very low probability
  //   of already ex
```