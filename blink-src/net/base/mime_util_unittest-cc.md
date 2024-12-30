Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The filename `mime_util_unittest.cc` immediately suggests this file tests the functionality of something related to MIME types. The `unittest` suffix confirms this. The `#include "net/base/mime_util.h"` further solidifies this, indicating that the unit tests are for the `mime_util.h` header file (likely containing the actual MIME utility implementations).

2. **Examine the Structure:** The file follows a standard Google Test structure:
    * Includes: Necessary headers like `mime_util.h`, standard library components (`vector`), Chromium base library components (`containers`, `files`, `strings`), build flags, and the Google Test framework headers (`gmock`, `gtest`).
    * Namespace: Everything is within the `net` namespace.
    * Test Fixtures (though minimal in this case):  While most tests are simple `TEST`, there are a couple of more structured tests using `TEST_P` and `INSTANTIATE_TEST_SUITE_P`, suggesting parameterization for those specific test cases.
    * Individual `TEST` macros: Each `TEST` macro represents a focused test of a particular function or aspect of the MIME utility.

3. **Analyze Individual Tests (Iterative Process):**  Go through each `TEST` function and determine what it's testing:
    * **`GetWellKnownMimeTypeFromExtension`:** Tests the function that maps file extensions to their most common MIME type. It uses a `tests` array with various extensions (including uppercase and one with a null byte) and their expected MIME types. The loop iterates through these and asserts the correctness of the `GetWellKnownMimeTypeFromExtension` function.
    * **`ExtensionTest`:** Similar to the previous test but tests `GetMimeTypeFromExtension`, which seems to return a *list* of possible MIME types for an extension (evident from the `std::vector<std::string>`). The test cases here also include platform-specific overrides (e.g., for ChromeOS).
    * **`GetPreferredExtensionForMimeType`:** Tests the reverse mapping – from MIME type to the preferred file extension.
    * **`FileTest`:** Tests `GetMimeTypeFromFile`, which extracts the MIME type based on the *filename*. This considers path information and focuses on the extension.
    * **`MatchesMimeType`:** Tests the `MatchesMimeType` function, which performs pattern matching on MIME types, including wildcards and parameters. This is a more complex matching logic.
    * **`TestParseMimeType`:** Tests `ParseMimeType`, which dissects a MIME type string into its base type and parameters. This involves handling quoted strings, whitespace, and various edge cases.
    * **`TestParseMimeTypeWithoutParameter`:** Tests `ParseMimeTypeWithoutParameter`, which focuses on validating the basic structure of a MIME type (type/subtype) without considering parameters.
    * **`ExtractMIMETypeTestInvalid` and `ExtractMIMETypeTestValid`:** These use parameterized tests (`TEST_P`) to check the `ExtractMimeTypeFromMediaType` function. One set tests *invalid* media type strings, and the other tests *valid* ones, ensuring the function correctly handles different input formats.
    * **`TestIsValidTopLevelMimeType`:** Tests the function that validates if a given string is a valid top-level MIME type (like "text", "image", etc.).
    * **`TestGetExtensionsForMimeType`:** Tests `GetExtensionsForMimeType`, which returns a list of all known extensions for a given MIME type.
    * **`TestGenerateMimeMultipartBoundary`:** Tests the generation of multipart boundaries, ensuring they meet RFC requirements (length, uniqueness) and have a recognizable pattern.
    * **`TestAddMultipartValueForUpload` and `TestAddMultipartValueForUploadWithFileName`:** Test functions responsible for constructing multipart form data, which is common for file uploads in HTTP requests.

4. **Identify JavaScript Relevance:**  Think about where MIME types are relevant in a web browser context and how they connect to JavaScript:
    * **Content-Type header:** This is the primary link. Browsers use the `Content-Type` header of HTTP responses to determine how to handle the data. JavaScript interacts with this when fetching resources (using `fetch` or `XMLHttpRequest`).
    * **File uploads:** When JavaScript uploads files, it often needs to construct `multipart/form-data` requests. The `AddMultipartValueForUpload` tests are directly relevant here.
    * **`<script>` tags:** The `type` attribute of a `<script>` tag specifies the MIME type of the script. Although "text/javascript" is common, other types exist.
    * **`createObjectURL`:**  This JavaScript API creates a URL representing a `Blob` or `File` object. The MIME type is a property of these objects.

5. **Consider Logic and Examples:**  For each test, think about:
    * **Assumptions:** What does the test assume about the input and the expected behavior of the function?
    * **Input/Output:** Can you provide simple examples of what input to a function would produce what output, based on the test cases?  For example,  `GetWellKnownMimeTypeFromExtension("png")` should output `"image/png"`.
    * **Edge cases:**  The tests often highlight edge cases (like null bytes in extensions, whitespace in MIME types, missing quotes).

6. **Identify User/Programming Errors:**  Think about common mistakes when dealing with MIME types:
    * **Incorrect extension:** Users might save a file with the wrong extension.
    * **Mismatched Content-Type:** The server might send the wrong `Content-Type` header.
    * **Case sensitivity:**  While MIME types are generally case-insensitive, developers might make mistakes with casing.
    * **Forgetting parameters:**  Some MIME types require parameters (like `charset`).
    * **Incorrect multipart construction:**  Manually building multipart data can be error-prone.

7. **Trace User Actions (Debugging):** Consider how a user's action in the browser might lead to the execution of these MIME utility functions:
    * **Downloading a file:** The browser uses the `Content-Type` to determine how to save the file.
    * **Opening a web page:** The browser parses the `Content-Type` of resources (HTML, CSS, JavaScript, images) to render the page correctly.
    * **Uploading a file:** JavaScript uses APIs to read the file and then constructs a request, potentially using the multipart functions.
    * **A `<script>` tag:**  The browser uses the `type` attribute to determine how to execute the script.

8. **Review and Organize:**  After analyzing the code, organize the findings into clear sections as requested by the prompt (functionality, JavaScript relation, logic examples, common errors, debugging). Use clear and concise language. Make sure to connect the test cases back to the actual functionality being tested.
This C++ source code file, `mime_util_unittest.cc`, is part of the Chromium project's network stack and contains unit tests for the functionality provided by `net/base/mime_util.h`. Essentially, it verifies that the MIME type utility functions in Chromium work correctly.

Here's a breakdown of its functionality:

**Core Functionality Under Test (based on the test names):**

* **Mapping File Extensions to MIME Types:**
    * `GetWellKnownMimeTypeFromExtension`: Tests the ability to retrieve the most common or "well-known" MIME type for a given file extension.
    * `GetMimeTypeFromExtension`: Tests retrieving a list of possible MIME types for a given file extension (potentially including platform-specific overrides).
    * `GetPreferredExtensionForMimeType`: Tests the reverse mapping, finding the preferred file extension for a given MIME type.
* **Determining MIME Type from File Path:**
    * `GetMimeTypeFromFile`: Tests extracting the MIME type based on a file's path and its extension.
* **Matching MIME Types:**
    * `MatchesMimeType`: Tests a function that determines if one MIME type pattern matches another, supporting wildcards and parameters.
* **Parsing MIME Type Strings:**
    * `ParseMimeType`: Tests parsing a full MIME type string (including parameters) into its base type and a list of key-value parameter pairs.
    * `ParseMimeTypeWithoutParameter`: Tests parsing a MIME type string without parameters, focusing on validating the basic type and subtype structure.
    * `ExtractMimeTypeFromMediaType`: Tests extracting the core MIME type from a media type string, which might include additional parameters.
* **Validating MIME Types:**
    * `IsValidTopLevelMimeType`: Tests whether a given string is a valid top-level MIME type (e.g., "text", "image").
* **Retrieving Extensions for a MIME Type:**
    * `GetExtensionsForMimeType`: Tests getting a list of file extensions associated with a given MIME type.
* **Generating Multipart Boundary Strings:**
    * `GenerateMimeMultipartBoundary`: Tests the generation of unique boundary strings used in `multipart/form-data` content.
* **Building Multipart Form Data:**
    * `AddMultipartValueForUpload`: Tests adding a single value (like a form field) to a multipart upload.
    * `AddMultipartValueForUploadWithFileName`: Tests adding a value representing a file (with a filename) to a multipart upload.

**Relationship with JavaScript Functionality:**

MIME types are crucial for web browsers and directly impact how JavaScript interacts with web resources. Here are examples:

* **`Content-Type` Header:** When JavaScript makes a request using `fetch` or `XMLHttpRequest`, the server responds with a `Content-Type` header. The browser uses these `mime_util` functions (like `ParseMimeType`, `MatchesMimeType`) to interpret this header and determine how to handle the data. For example:
    * If the `Content-Type` is `application/json`, JavaScript might automatically parse the response body as JSON.
    * If the `Content-Type` is `text/javascript`, the browser knows it's a script that needs to be executed.
* **`<script>` Tag:** The `type` attribute of a `<script>` tag specifies the MIME type of the script. While often "text/javascript", other types might be used for module scripts or other script languages. The `mime_util` functions help the browser understand the script's type.
    ```html
    <script type="text/javascript">
      // JavaScript code
    </script>
    <script type="module">
      // JavaScript module code
    </script>
    ```
* **File Uploads (`<input type="file">` and `FormData`):** When JavaScript uploads files using a form or the `FormData` API, the browser constructs a `multipart/form-data` request. Functions like `AddMultipartValueForUpload` are involved in creating the correct structure of this request, including setting the appropriate `Content-Type` for each part.
    ```javascript
    const formData = new FormData();
    const fileInput = document.getElementById('fileInput');
    formData.append('file', fileInput.files[0]); // The browser needs to determine the file's MIME type

    fetch('/upload', {
      method: 'POST',
      body: formData
    });
    ```
* **`createObjectURL` and `Blob`:**  When JavaScript creates a `Blob` object (representing raw data) or gets a `File` object (inheriting from `Blob`), the MIME type is a crucial property. Functions in `mime_util` might be used internally to determine or validate these MIME types.
    ```javascript
    const blob = new Blob(['<h1>Hello, world!</h1>'], { type: 'text/html' });
    const url = URL.createObjectURL(blob); // The browser needs to know the Blob's type
    ```

**Logical Reasoning with Assumptions, Input, and Output:**

Let's take the `GetWellKnownMimeTypeFromExtension` test as an example:

* **Assumption:** The function `GetWellKnownMimeTypeFromExtension` correctly maps common file extensions to their standard MIME types.
* **Hypothetical Input:** The extension is "jpg".
* **Expected Output:** The function should return the string "image/jpeg".

Another example, using `MatchesMimeType`:

* **Assumption:** The `MatchesMimeType` function correctly implements MIME type matching logic, including wildcard support.
* **Hypothetical Input:** `MatchesMimeType("image/*", "image/png")`
* **Expected Output:** `true` (because "image/png" matches the pattern "image/*").

**User or Programming Common Usage Errors:**

* **Incorrect File Extension:** A user might rename a file and give it an incorrect extension. For example, a PNG image might be accidentally named `myimage.txt`. The `GetMimeTypeFromFile` function would likely return `text/plain` in this case, which could lead to the browser misinterpreting the file content.
* **Mismatched `Content-Type` on the Server:** A server might be misconfigured and send the wrong `Content-Type` header for a resource. For example, a JavaScript file might be served with `Content-Type: text/plain`. This would cause the browser to treat the JavaScript code as plain text and not execute it.
* **Forgetting to Set `Content-Type` in `fetch` or `XMLHttpRequest`:** When making manual requests in JavaScript, developers need to set the `Content-Type` header in the request if they are sending data (e.g., in a `POST` request). Forgetting this can lead to the server misinterpreting the data.
    ```javascript
    fetch('/api/data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json' // Important!
      },
      body: JSON.stringify({ key: 'value' })
    });
    ```
* **Incorrectly Constructing `multipart/form-data`:** When manually building `multipart/form-data` (though less common now with the `FormData` API), developers might make mistakes in formatting the boundary, headers, or data parts. The tests for `AddMultipartValueForUpload` aim to prevent errors in the underlying implementation of this process.

**User Operations Leading to This Code (Debugging Clues):**

Let's trace a scenario where these MIME utility functions might be invoked during a user's action:

1. **User downloads a file:**
   * The user clicks a link to a file (e.g., an image or a PDF).
   * The browser sends a request to the server.
   * The server responds with the file content and a `Content-Type` header.
   * The network stack in Chromium receives the response.
   * Functions like `ParseMimeType` are used to parse the `Content-Type` header.
   * Based on the parsed MIME type, the browser decides how to handle the download (e.g., display it inline, download it to the disk, use a specific plugin).
   * If the user later tries to open this downloaded file, functions like `GetMimeTypeFromFile` might be used by the operating system or other applications to determine the file type based on its extension.

2. **User uploads a file:**
   * The user interacts with an `<input type="file">` element on a web page and selects a file.
   * JavaScript code on the page might use the `FormData` API to prepare the data for upload.
   * Internally, the browser (using code similar to the tested functions) determines the MIME type of the selected file (likely using `GetMimeTypeFromExtension` based on the file's extension).
   * When the form is submitted or the `fetch` API is used to send the data, the browser constructs a `multipart/form-data` request, using functions like `AddMultipartValueForUpload` to format the request body correctly, including the file's MIME type in the `Content-Type` header of the relevant part.

3. **Browser renders a web page:**
   * The browser receives the HTML content of a web page (likely with `Content-Type: text/html`).
   * The HTML parser encounters `<link>` tags for CSS files or `<script>` tags for JavaScript files.
   * For each such resource, the browser makes a separate request.
   * The server responds with the CSS or JavaScript content and a corresponding `Content-Type` header (e.g., `text/css`, `text/javascript`, `application/javascript`).
   * The `mime_util` functions are used to parse these `Content-Type` headers to determine how to process the resources (e.g., apply CSS styles, execute JavaScript code).

By examining the unit tests in `mime_util_unittest.cc`, we gain insight into the various scenarios and edge cases that the Chromium developers considered when implementing the MIME type handling logic in the browser. This helps ensure reliable and correct interpretation of web resources.

Prompt: 
```
这是目录为net/base/mime_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/mime_util.h"

#include <vector>

#include "base/containers/contains.h"
#include "base/files/file_path.h"
#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

using testing::Contains;

TEST(MimeUtilTest, GetWellKnownMimeTypeFromExtension) {
  // String: png\0css
  base::FilePath::StringType containsNullByte;
  containsNullByte.append(FILE_PATH_LITERAL("png"));
  containsNullByte.append(1, FILE_PATH_LITERAL('\0'));
  containsNullByte.append(FILE_PATH_LITERAL("css"));

  const struct {
    const base::FilePath::StringType extension;
    const char* const mime_type;
  } tests[] = {
      {FILE_PATH_LITERAL("png"), "image/png"},
      {FILE_PATH_LITERAL("PNG"), "image/png"},
      {FILE_PATH_LITERAL("css"), "text/css"},
      {FILE_PATH_LITERAL("pjp"), "image/jpeg"},
      {FILE_PATH_LITERAL("pjpeg"), "image/jpeg"},
      {FILE_PATH_LITERAL("json"), "application/json"},
      {FILE_PATH_LITERAL("js"), "text/javascript"},
      {FILE_PATH_LITERAL("webm"), "video/webm"},
      {FILE_PATH_LITERAL("weba"), "audio/webm"},
      {FILE_PATH_LITERAL("avif"), "image/avif"},
      {FILE_PATH_LITERAL("epub"), "application/epub+zip"},
      {FILE_PATH_LITERAL("apk"), "application/vnd.android.package-archive"},
      {FILE_PATH_LITERAL("cer"), "application/x-x509-ca-cert"},
      {FILE_PATH_LITERAL("crt"), "application/x-x509-ca-cert"},
      {FILE_PATH_LITERAL("zip"), "application/zip"},
      {FILE_PATH_LITERAL("ics"), "text/calendar"},
      {FILE_PATH_LITERAL("m3u8"), "application/x-mpegurl"},
      {FILE_PATH_LITERAL("csv"), "text/csv"},
      {FILE_PATH_LITERAL("not an extension / for sure"), nullptr},
      {containsNullByte, nullptr}};

  for (const auto& test : tests) {
    std::string mime_type;
    if (GetWellKnownMimeTypeFromExtension(test.extension, &mime_type))
      EXPECT_EQ(test.mime_type, mime_type);
    else
      EXPECT_EQ(test.mime_type, nullptr);
  }
}

TEST(MimeUtilTest, ExtensionTest) {
  // String: png\0css
  base::FilePath::StringType containsNullByte;
  containsNullByte.append(FILE_PATH_LITERAL("png"));
  containsNullByte.append(1, FILE_PATH_LITERAL('\0'));
  containsNullByte.append(FILE_PATH_LITERAL("css"));

  const struct {
    const base::FilePath::StringType extension;
    const std::vector<std::string> mime_types;
  } tests[] = {
    {FILE_PATH_LITERAL("png"), {"image/png"}},
    {FILE_PATH_LITERAL("PNG"), {"image/png"}},
    {FILE_PATH_LITERAL("css"), {"text/css"}},
    {FILE_PATH_LITERAL("pjp"), {"image/jpeg"}},
    {FILE_PATH_LITERAL("pjpeg"), {"image/jpeg"}},
    {FILE_PATH_LITERAL("json"), {"application/json"}},
    {FILE_PATH_LITERAL("js"), {"text/javascript"}},
    {FILE_PATH_LITERAL("webm"), {"video/webm"}},
    {FILE_PATH_LITERAL("weba"), {"audio/webm"}},
    {FILE_PATH_LITERAL("avif"), {"image/avif"}},
#if BUILDFLAG(IS_CHROMEOS_ASH)
    // These are test cases for testing platform mime types on ChromeOS.
    {FILE_PATH_LITERAL("epub"), {"application/epub+zip"}},
    {FILE_PATH_LITERAL("apk"), {"application/vnd.android.package-archive"}},
    {FILE_PATH_LITERAL("cer"),
     {
         "application/x-x509-ca-cert",
         "application/pkix-cert",  // System override for ChromeOS.
     }},
    {FILE_PATH_LITERAL("crt"),
     {
         "application/x-x509-ca-cert",
         "application/pkix-cert",  // System override for ChromeOS.
     }},
    {FILE_PATH_LITERAL("zip"), {"application/zip"}},
    {FILE_PATH_LITERAL("ics"), {"text/calendar"}},
#endif
    {FILE_PATH_LITERAL("m3u8"),
     {
         "application/x-mpegurl",  // Chrome's secondary mapping.
         "audio/x-mpegurl",  // https://crbug.com/1273061, system override for
                             // android-arm[64]-test and Linux. Possibly more.
         "audio/mpegurl",                  // System override for mac.
     }},
    {FILE_PATH_LITERAL("csv"), {"text/csv"}},
    {FILE_PATH_LITERAL("not an extension / for sure"), {}},
    {containsNullByte, {}}
  };

  for (const auto& test : tests) {
    std::string mime_type;
    if (GetMimeTypeFromExtension(test.extension, &mime_type))
      EXPECT_THAT(test.mime_types, Contains(mime_type));
    else
      EXPECT_TRUE(test.mime_types.empty());
  }
}

// Behavior of GetPreferredExtensionForMimeType() is dependent on the host
// platform since the latter can override the mapping from file extensions to
// MIME types. The tests below would only work if the platform MIME mappings
// don't have mappings for or has an agreeing mapping for each MIME type
// mentioned.
TEST(MimeUtilTest, GetPreferredExtensionForMimeType) {
  const struct {
    const std::string mime_type;
    const base::FilePath::StringType expected_extension;
  } kTestCases[] = {
      {"application/wasm", FILE_PATH_LITERAL("wasm")},      // Primary
      {"application/javascript", FILE_PATH_LITERAL("js")},  // Secondary
      {"text/javascript", FILE_PATH_LITERAL("js")},         // Primary
      {"video/webm", FILE_PATH_LITERAL("webm")},            // Primary
  };

  for (const auto& test : kTestCases) {
    base::FilePath::StringType extension;
    auto rv = GetPreferredExtensionForMimeType(test.mime_type, &extension);
    EXPECT_TRUE(rv);
    EXPECT_EQ(test.expected_extension, extension);
  }
}

TEST(MimeUtilTest, FileTest) {
  const struct {
    const base::FilePath::CharType* file_path;
    const char* const mime_type;
    bool valid;
  } tests[] = {
      {FILE_PATH_LITERAL("c:\\foo\\bar.css"), "text/css", true},
      {FILE_PATH_LITERAL("c:\\foo\\bar.CSS"), "text/css", true},
      {FILE_PATH_LITERAL("c:\\blah"), "", false},
      {FILE_PATH_LITERAL("/usr/local/bin/mplayer"), "", false},
      {FILE_PATH_LITERAL("/home/foo/bar.css"), "text/css", true},
      {FILE_PATH_LITERAL("/blah."), "", false},
      {FILE_PATH_LITERAL("c:\\blah."), "", false},
  };

  std::string mime_type;
  bool rv;

  for (const auto& test : tests) {
    rv = GetMimeTypeFromFile(base::FilePath(test.file_path), &mime_type);
    EXPECT_EQ(test.valid, rv);
    if (rv)
      EXPECT_EQ(test.mime_type, mime_type);
  }
}

TEST(MimeUtilTest, MatchesMimeType) {
  // MIME types are case insensitive.
  EXPECT_TRUE(MatchesMimeType("VIDEO/*", "video/x-mpeg"));
  EXPECT_TRUE(MatchesMimeType("video/*", "VIDEO/X-MPEG"));

  EXPECT_TRUE(MatchesMimeType("*", "video/x-mpeg"));
  EXPECT_TRUE(MatchesMimeType("video/*", "video/x-mpeg"));
  EXPECT_TRUE(MatchesMimeType("video/*", "video/*"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg", "video/x-mpeg"));
  EXPECT_TRUE(MatchesMimeType("application/*+xml",
                                   "application/html+xml"));
  EXPECT_TRUE(MatchesMimeType("application/*+xml", "application/+xml"));
  EXPECT_TRUE(MatchesMimeType("application/*+json",
                                   "application/x-myformat+json"));
  EXPECT_TRUE(MatchesMimeType("aaa*aaa", "aaaaaa"));
  EXPECT_TRUE(MatchesMimeType("*", std::string()));
  EXPECT_FALSE(MatchesMimeType("video/", "video/x-mpeg"));
  EXPECT_FALSE(MatchesMimeType("VIDEO/", "Video/X-MPEG"));
  EXPECT_FALSE(MatchesMimeType(std::string(), "video/x-mpeg"));
  EXPECT_FALSE(MatchesMimeType(std::string(), std::string()));
  EXPECT_FALSE(MatchesMimeType("video/x-mpeg", std::string()));
  EXPECT_FALSE(MatchesMimeType("application/*+xml", "application/xml"));
  EXPECT_FALSE(MatchesMimeType("application/*+xml",
                                    "application/html+xmlz"));
  EXPECT_FALSE(MatchesMimeType("application/*+xml",
                                    "applcation/html+xml"));
  EXPECT_FALSE(MatchesMimeType("aaa*aaa", "aaaaa"));

  EXPECT_TRUE(MatchesMimeType("*", "video/x-mpeg;param=val"));
  EXPECT_TRUE(MatchesMimeType("*", "Video/X-MPEG;PARAM=VAL"));
  EXPECT_TRUE(MatchesMimeType("video/*", "video/x-mpeg;param=val"));
  EXPECT_FALSE(MatchesMimeType("video/*;param=val", "video/mpeg"));
  EXPECT_FALSE(MatchesMimeType("Video/*;PARAM=VAL", "VIDEO/Mpeg"));
  EXPECT_FALSE(MatchesMimeType("video/*;param=val", "video/mpeg;param=other"));
  EXPECT_TRUE(MatchesMimeType("video/*;param=val", "video/mpeg;param=val"));
  EXPECT_TRUE(MatchesMimeType("Video/*;PARAM=Val", "VIDEO/Mpeg;Param=Val"));
  EXPECT_FALSE(MatchesMimeType("Video/*;PARAM=VAL", "VIDEO/Mpeg;Param=Val"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg", "video/x-mpeg;param=val"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg;param=val",
                              "video/x-mpeg;param=val"));
  EXPECT_FALSE(MatchesMimeType("video/x-mpeg;param2=val2",
                               "video/x-mpeg;param=val"));
  EXPECT_FALSE(MatchesMimeType("video/x-mpeg;param2=val2",
                               "video/x-mpeg;param2=val"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg;param=val",
                              "video/x-mpeg;param=val;param2=val2"));
  EXPECT_TRUE(MatchesMimeType("Video/X-Mpeg;Param=Val",
                              "VIDEO/X-MPEG;PARAM=Val;PARAM2=val2"));
  EXPECT_TRUE(MatchesMimeType("Video/X-Mpeg;Param=VAL",
                              "VIDEO/X-MPEG;PARAM=VAL;PARAM2=val2"));
  EXPECT_FALSE(MatchesMimeType("Video/X-Mpeg;Param=val",
                               "VIDEO/X-MPEG;PARAM=VAL;PARAM2=val2"));
  EXPECT_FALSE(MatchesMimeType("video/x-mpeg;param=VAL;param2=val2",
                               "video/x-mpeg;param=val;param2=val2"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg;param2=val2;param=val",
                              "video/x-mpeg;param=val;param2=val2"));
  EXPECT_FALSE(MatchesMimeType("video/x-mpeg;param3=val3;param=val",
                               "video/x-mpeg;param=val;param2=val2"));
  EXPECT_TRUE(MatchesMimeType("video/x-mpeg;param=val ;param2=val2 ",
                              "video/x-mpeg;param=val;param2=val2"));

  EXPECT_TRUE(MatchesMimeType("*/*;param=val", "video/x-mpeg;param=val"));
  EXPECT_FALSE(MatchesMimeType("*/*;param=val", "video/x-mpeg;param=val2"));

  EXPECT_TRUE(MatchesMimeType("*", "*"));
  EXPECT_TRUE(MatchesMimeType("*", "*/*"));
  EXPECT_TRUE(MatchesMimeType("*/*", "*/*"));
  EXPECT_TRUE(MatchesMimeType("*/*", "*"));
  EXPECT_TRUE(MatchesMimeType("video/*", "video/*"));
  EXPECT_FALSE(MatchesMimeType("video/*", "*/*"));
  EXPECT_FALSE(MatchesMimeType("video/*;param=val", "video/*"));
  EXPECT_TRUE(MatchesMimeType("video/*;param=val", "video/*;param=val"));
  EXPECT_FALSE(MatchesMimeType("video/*;param=val", "video/*;param=val2"));

  EXPECT_TRUE(MatchesMimeType("ab*cd", "abxxxcd"));
  EXPECT_TRUE(MatchesMimeType("ab*cd", "abx/xcd"));
  EXPECT_TRUE(MatchesMimeType("ab/*cd", "ab/xxxcd"));
}

TEST(MimeUtilTest, TestParseMimeType) {
  const struct {
    std::string type_str;
    std::string mime_type;
    base::StringPairs params;
  } tests[] = {
      // Simple tests.
      {"image/jpeg", "image/jpeg"},
      {"application/octet-stream;foo=bar;name=\"test.jpg\"",
       "application/octet-stream",
       {{"foo", "bar"}, {"name", "test.jpg"}}},
      // Quoted string parsing.
      {"t/s;name=\"t\\\\est\\\".jpg\"", "t/s", {{"name", "t\\est\".jpg"}}},
      {"t/s;name=\"test.jpg\"", "t/s", {{"name", "test.jpg"}}},
      {"t/s;name=\"test;jpg\"", "t/s", {{"name", "test;jpg"}}},
      // Lenient for no closing quote.
      {"t/s;name=\"test.jpg", "t/s", {{"name", "test.jpg"}}},
      {"t/s;name=\"ab\\\"", "t/s", {{"name", "ab\""}}},
      // Strip whitespace from start/end of mime_type.
      {" t/s", "t/s"},
      {"t/s ", "t/s"},
      {" t/s ", "t/s"},
      {"t/=", "t/="},
      // Generally ignore whitespace.
      {"t/s;a=1;b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      {"t/s ;a=1;b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      {"t/s; a=1;b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      // Special case, include whitespace after param name until equals.
      {"t/s;a =1;b=2", "t/s", {{"a ", "1"}, {"b", "2"}}},
      {"t/s;a= 1;b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      {"t/s;a=1 ;b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      {"t/s;a=1; b=2", "t/s", {{"a", "1"}, {"b", "2"}}},
      {"t/s; a = 1;b=2", "t/s", {{"a ", "1"}, {"b", "2"}}},
      // Do not trim whitespace from quoted-string param values.
      {"t/s;a=\" 1\";b=2", "t/s", {{"a", " 1"}, {"b", "2"}}},
      {"t/s;a=\"1 \";b=2", "t/s", {{"a", "1 "}, {"b", "2"}}},
      {"t/s;a=\" 1 \";b=2", "t/s", {{"a", " 1 "}, {"b", "2"}}},
      // Ignore incomplete params.
      {"t/s;a", "t/s", {}},
      {"t/s;a=", "t/s", {}},
      {"t/s;a=1;", "t/s", {{"a", "1"}}},
      {"t/s;a=1;b", "t/s", {{"a", "1"}}},
      {"t/s;a=1;b=", "t/s", {{"a", "1"}}},
      // Allow empty subtype.
      {"t/", "t/", {}},
      {"ts/", "ts/", {}},
      {"t/;", "t/", {}},
      {"t/ s", "t/", {}},
      // Questionable: allow anything as long as there is a slash somewhere.
      {"/ts", "/ts", {}},
      {"/s", "/s", {}},
      {"/", "/", {}},
  };
  for (const auto& test : tests) {
    std::string mime_type;
    base::StringPairs params;
    EXPECT_TRUE(ParseMimeType(test.type_str, &mime_type, &params));
    EXPECT_EQ(test.mime_type, mime_type);
    EXPECT_EQ(test.params, params);
  }
  for (auto* type_str : {
           // Must have slash in mime type.
           "",
           "ts",
           "t / s",
       }) {
    EXPECT_FALSE(ParseMimeType(type_str, nullptr, nullptr));
  }
}

TEST(MimeUtilTest, TestParseMimeTypeWithoutParameter) {
  std::string nonAscii("application/nonutf8");
  EXPECT_TRUE(ParseMimeTypeWithoutParameter(nonAscii, nullptr, nullptr));
#if BUILDFLAG(IS_WIN)
  nonAscii.append(base::WideToUTF8(L"\u2603"));
#else
  nonAscii.append("\u2603");  // unicode snowman
#endif
  EXPECT_FALSE(ParseMimeTypeWithoutParameter(nonAscii, nullptr, nullptr));

  std::string top_level_type;
  std::string subtype;
  EXPECT_TRUE(ParseMimeTypeWithoutParameter(
      "application/mime", &top_level_type, &subtype));
  EXPECT_EQ("application", top_level_type);
  EXPECT_EQ("mime", subtype);

  // Various allowed subtype forms.
  EXPECT_TRUE(
      ParseMimeTypeWithoutParameter("application/json", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("application/x-suggestions+json",
                                            nullptr, nullptr));
  EXPECT_TRUE(
      ParseMimeTypeWithoutParameter("application/+json", nullptr, nullptr));

  // Upper case letters are allowed.
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/mime", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("TEXT/mime", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("Text/mime", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("TeXt/mime", nullptr, nullptr));

  // Experimental types are also considered to be valid.
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("x-video/mime", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("X-Video/mime", nullptr, nullptr));

  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text/", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text/ ", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("te(xt/ ", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text/()plain", nullptr, nullptr));

  EXPECT_FALSE(ParseMimeTypeWithoutParameter("x-video", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("x-video/", nullptr, nullptr));

  EXPECT_FALSE(
      ParseMimeTypeWithoutParameter("application/a/b/c", nullptr, nullptr));

  // Test leading and trailing whitespace
  EXPECT_TRUE(ParseMimeTypeWithoutParameter(" text/plain", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/plain ", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text /plain", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text/ plain ", nullptr, nullptr));

  EXPECT_TRUE(ParseMimeTypeWithoutParameter("\ttext/plain", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/plain\t", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text\t/plain", nullptr, nullptr));
  EXPECT_FALSE(
      ParseMimeTypeWithoutParameter("text/\tplain ", nullptr, nullptr));

  EXPECT_TRUE(ParseMimeTypeWithoutParameter("\vtext/plain", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/plain\v", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text\v/plain", nullptr, nullptr));
  EXPECT_FALSE(
      ParseMimeTypeWithoutParameter("text/\vplain ", nullptr, nullptr));

  EXPECT_TRUE(ParseMimeTypeWithoutParameter("\rtext/plain", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/plain\r", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text\r/plain", nullptr, nullptr));
  EXPECT_FALSE(
      ParseMimeTypeWithoutParameter("text/\rplain ", nullptr, nullptr));

  EXPECT_TRUE(ParseMimeTypeWithoutParameter("\ntext/plain", nullptr, nullptr));
  EXPECT_TRUE(ParseMimeTypeWithoutParameter("text/plain\n", nullptr, nullptr));
  EXPECT_FALSE(ParseMimeTypeWithoutParameter("text\n/plain", nullptr, nullptr));
  EXPECT_FALSE(
      ParseMimeTypeWithoutParameter("text/\nplain ", nullptr, nullptr));
}

class ExtractMIMETypeTestInvalid : public testing::TestWithParam<std::string> {
};

INSTANTIATE_TEST_SUITE_P(
    InvalidMediaTypes,
    ExtractMIMETypeTestInvalid,
    testing::Values(
        // Fails because it doesn't contain '/'.
        "a",
        "application",
        // Space is not HTTP token code point.
        //  https://mimesniff.spec.whatwg.org/#http-token-code-point
        // U+2003, EM SPACE (UTF-8: E2 80 83).
        "\xE2\x80\x83text/html",
        "text\xE2\x80\x83/html",
        "text / html",
        "t e x t / h t m l",
        "text\r\n/\nhtml",
        "text\n/\nhtml",
        ", text/html",
        "; text/html"));

TEST_P(ExtractMIMETypeTestInvalid, MustFail) {
  // Parsing is expected to fail.
  EXPECT_EQ(std::nullopt, net::ExtractMimeTypeFromMediaType(GetParam(), true));
}

class ExtractMIMETypeTestValid : public testing::TestWithParam<std::string> {};

INSTANTIATE_TEST_SUITE_P(
    ValidMediaTypes,
    ExtractMIMETypeTestValid,
    testing::Values("text/html",
                    "text/html; charset=iso-8859-1",
                    // Quoted charset parameter.
                    "text/html; charset=\"quoted\"",
                    // Multiple parameters.
                    "text/html; charset=x; foo=bar",
                    // OWSes are trimmed.
                    " text/html   ",
                    "\ttext/html \t",
                    "text/html ; charset=iso-8859-1"
                    // Non-standard multiple type/subtype listing using a comma
                    // as a separator is accepted.
                    "text/html,text/plain",
                    "text/html , text/plain",
                    "text/html\t,\ttext/plain",
                    "text/html,text/plain;charset=iso-8859-1",
                    "\r\ntext/html\r\n",
                    "text/html;wow",
                    "text/html;;;;;;",
                    "text/html; = = = "));

TEST_P(ExtractMIMETypeTestValid, MustSucceed) {
  //  net::ExtractMIMETypeFromMediaType parses well-formed headers correctly.
  EXPECT_EQ("text/html",
            net::ExtractMimeTypeFromMediaType(GetParam(), true).value_or(""));
}

TEST(MimeUtilTest, TestIsValidTopLevelMimeType) {
  EXPECT_TRUE(IsValidTopLevelMimeType("application"));
  EXPECT_TRUE(IsValidTopLevelMimeType("audio"));
  EXPECT_TRUE(IsValidTopLevelMimeType("example"));
  EXPECT_TRUE(IsValidTopLevelMimeType("font"));
  EXPECT_TRUE(IsValidTopLevelMimeType("image"));
  EXPECT_TRUE(IsValidTopLevelMimeType("message"));
  EXPECT_TRUE(IsValidTopLevelMimeType("model"));
  EXPECT_TRUE(IsValidTopLevelMimeType("multipart"));
  EXPECT_TRUE(IsValidTopLevelMimeType("text"));
  EXPECT_TRUE(IsValidTopLevelMimeType("video"));

  EXPECT_TRUE(IsValidTopLevelMimeType("TEXT"));
  EXPECT_TRUE(IsValidTopLevelMimeType("Text"));
  EXPECT_TRUE(IsValidTopLevelMimeType("TeXt"));

  EXPECT_FALSE(IsValidTopLevelMimeType("mime"));
  EXPECT_FALSE(IsValidTopLevelMimeType(""));
  EXPECT_FALSE(IsValidTopLevelMimeType("/"));
  EXPECT_FALSE(IsValidTopLevelMimeType(" "));

  EXPECT_TRUE(IsValidTopLevelMimeType("x-video"));
  EXPECT_TRUE(IsValidTopLevelMimeType("X-video"));

  EXPECT_FALSE(IsValidTopLevelMimeType("x-"));
}

TEST(MimeUtilTest, TestGetExtensionsForMimeType) {
  const struct {
    const char* const mime_type;
    size_t min_expected_size;
    const char* const contained_result;
    bool no_matches;
  } tests[] = {
      {"text/plain", 2, "txt"},
      {"text/pl", 0, nullptr, true},
      {"*", 0, nullptr},
      {"", 0, nullptr, true},
      {"message/*", 1, "eml"},
      {"MeSsAge/*", 1, "eml"},
      {"message/", 0, nullptr, true},
      {"image/avif", 1, "avif"},
      {"image/bmp", 1, "bmp"},
      {"video/*", 6, "mp4"},
      {"video/*", 6, "mpeg"},
      {"audio/*", 6, "oga"},
      {"aUDIo/*", 6, "wav"},
  };

  for (const auto& test : tests) {
    std::vector<base::FilePath::StringType> extensions;
    GetExtensionsForMimeType(test.mime_type, &extensions);
    ASSERT_LE(test.min_expected_size, extensions.size());

    if (test.no_matches)
      ASSERT_EQ(0u, extensions.size());

    if (test.contained_result) {
      bool found = base::Contains(
          extensions, base::FilePath::FromASCII(test.contained_result).value());

      ASSERT_TRUE(found) << "Must find at least the contained result within "
                         << test.mime_type;
    }
  }
}

TEST(MimeUtilTest, TestGenerateMimeMultipartBoundary) {
  std::string boundary1 = GenerateMimeMultipartBoundary();
  std::string boundary2 = GenerateMimeMultipartBoundary();

  // RFC 1341 says: the boundary parameter [...] consists of 1 to 70 characters.
  EXPECT_GE(70u, boundary1.size());
  EXPECT_GE(70u, boundary2.size());

  // RFC 1341 asks to: exercise care to choose a unique boundary.
  EXPECT_NE(boundary1, boundary2);
  ASSERT_LE(16u, boundary1.size());
  ASSERT_LE(16u, boundary2.size());

  // Expect that we don't pick '\0' character from the array/string
  // where we take the characters from.
  EXPECT_EQ(std::string::npos, boundary1.find('\0'));
  EXPECT_EQ(std::string::npos, boundary2.find('\0'));

  // Asserts below are not RFC 1341 requirements, but are here
  // to improve readability of generated MIME documents and to
  // try to preserve some aspects of the old boundary generation code.
  EXPECT_EQ("--", boundary1.substr(0, 2));
  EXPECT_EQ("--", boundary2.substr(0, 2));
  EXPECT_NE(std::string::npos, boundary1.find("MultipartBoundary"));
  EXPECT_NE(std::string::npos, boundary2.find("MultipartBoundary"));
  EXPECT_EQ("--", boundary1.substr(boundary1.size() - 2, 2));
  EXPECT_EQ("--", boundary2.substr(boundary2.size() - 2, 2));
}

TEST(MimeUtilTest, TestAddMultipartValueForUpload) {
  const char ref_output[] =
      "--boundary\r\nContent-Disposition: form-data;"
      " name=\"value name\"\r\nContent-Type: content type"
      "\r\n\r\nvalue\r\n"
      "--boundary\r\nContent-Disposition: form-data;"
      " name=\"value name\"\r\n\r\nvalue\r\n"
      "--boundary--\r\n";
  std::string post_data;
  AddMultipartValueForUpload("value name", "value", "boundary",
                             "content type", &post_data);
  AddMultipartValueForUpload("value name", "value", "boundary",
                             "", &post_data);
  AddMultipartFinalDelimiterForUpload("boundary", &post_data);
  EXPECT_STREQ(ref_output, post_data.c_str());
}

TEST(MimeUtilTest, TestAddMultipartValueForUploadWithFileName) {
  const char ref_output[] =
      "--boundary\r\nContent-Disposition: form-data;"
      " name=\"value name\"; filename=\"file name\"\r\nContent-Type: content "
      "type"
      "\r\n\r\nvalue\r\n"
      "--boundary\r\nContent-Disposition: form-data;"
      " name=\"value name\"; filename=\"file name\"\r\n\r\nvalue\r\n"
      "--boundary--\r\n";
  std::string post_data;
  AddMultipartValueForUploadWithFileName("value name", "file name", "value",
                                         "boundary", "content type",
                                         &post_data);
  AddMultipartValueForUploadWithFileName("value name", "file name", "value",
                                         "boundary", "", &post_data);
  AddMultipartFinalDelimiterForUpload("boundary", &post_data);
  EXPECT_STREQ(ref_output, post_data.c_str());
}
}  // namespace net

"""

```