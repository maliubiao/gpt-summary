Response: Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The primary goal is to understand what the `page_state_serialization.cc` file does in the Chromium Blink engine. This involves identifying its core function, its relationship to web technologies (JavaScript, HTML, CSS), and potential pitfalls for users or developers.

2. **Initial Code Scan - Keywords and Structure:**  Start by skimming the code for prominent keywords and structural elements. This includes:
    * `#include` directives: These reveal dependencies and hint at the file's purpose (e.g., `page_state.mojom.h`, `base/pickle.h`, `url/mojom/url_gurl_mojom_traits.h`). The inclusion of `page_state.mojom.h` strongly suggests this file is about serializing and deserializing page state.
    * Namespace `blink`: This confirms the file is part of the Blink rendering engine.
    * Functions with "Write" and "Read" prefixes (e.g., `WriteData`, `ReadInteger`, `WriteLegacyFrameState`, `ReadMojoFrameState`):  This reinforces the serialization/deserialization theme. The presence of "Legacy" and "Mojo" prefixes hints at different serialization methods, likely an older and a newer one.
    * The `SerializeObject` struct: This seems to be a central data structure for managing the serialization process using `base::Pickle`.
    * Versioning (`kMinVersion`, `kCurrentVersion`):  This indicates a need for backwards compatibility, as the serialization format has evolved.
    * Functions like `EncodePageState`, `DecodePageState`: These are high-level functions for performing the overall serialization and deserialization.
    * Use of `mojom`:  This points to the use of Mojo interfaces for inter-process communication and data serialization within Chromium.

3. **Identify the Core Functionality:** Based on the initial scan, the central function is clearly **serializing and deserializing the state of a web page**. This "page state" likely includes information needed to restore a page to a previous state, such as scroll position, form data, and potentially more.

4. **Analyze Key Data Structures:**
    * `ExplodedPageState`:  This seems to be an in-memory representation of the page state before/after serialization.
    * `ExplodedFrameState`:  This likely represents the state of an individual frame within a page. The nested structure (`children`) suggests handling of iframes.
    * `ExplodedHttpBody`: This likely stores information about the HTTP request body associated with a page or frame.
    * `mojom::PageState`, `mojom::FrameState`, `mojom::HttpBody`, `mojom::RequestBody`, `mojom::Element`: These are Mojo data structures representing the page state components in a more structured and modern way.
    * `SerializeObject`:  This helper manages the `base::Pickle` object for writing and reading binary data.

5. **Connect to Web Technologies:**  Consider how the serialized data relates to JavaScript, HTML, and CSS:
    * **JavaScript:** The "state object" (`state_object`) is directly related to `history.pushState()` and `history.replaceState()`. Form data and scroll position are also affected by JavaScript interactions. The "navigation API key/state/id" directly link to JavaScript's Navigation API.
    * **HTML:** Form data within `<form>` elements is clearly captured (`document_state`). The URL, target frame, and referrer are attributes of HTML elements or the browsing context. The handling of iframes and their states directly relates to HTML structure.
    * **CSS:** While CSS itself isn't directly serialized in this file (it's about *state*, not presentation), the *effects* of CSS are reflected in things like scroll position and potentially visual viewport offsets. The "visual viewport scroll offset" is relevant when considering zooming, which can be influenced by CSS.

6. **Trace the Serialization/Deserialization Logic:**
    * **Legacy vs. Mojo:** The code clearly distinguishes between older (legacy) and newer (Mojo-based) serialization methods. This is important for understanding the evolution of the code and maintaining backwards compatibility.
    * **`WriteLegacyPageState`/`ReadLegacyPageState`:** These functions handle the older, custom binary format using `base::Pickle` directly.
    * **`WriteMojoPageState`/`ReadMojoPageState`:** These functions use the more structured Mojo interfaces for serialization.
    * **Versioning:** The version number is crucial for determining which read/write path to take.
    * **Pickling:** The `base::Pickle` class is used as the underlying mechanism for serializing primitive data types and strings.

7. **Identify Potential Issues and Edge Cases:**
    * **Backwards Compatibility:** The versioning system and separate legacy/Mojo code highlight the importance of maintaining compatibility with older serialized data.
    * **Data Corruption:** Parsing errors (`obj.parse_error`) can occur if the serialized data is corrupted or malformed. The code attempts to handle these gracefully by returning default values.
    * **Size Limits:**  The code includes checks for vector sizes and string lengths to prevent excessive memory allocation or potential buffer overflows (e.g., `kMaxScrollAnchorSelectorLength`).
    * **User/Developer Errors:**  Common mistakes could involve:
        * Modifying the serialization format without incrementing the version number.
        * Incorrectly interpreting the serialized data format.
        * Relying on specific serialization details that might change in future versions.
        * Issues with handling file paths and modifications.

8. **Construct Examples and Hypothetical Scenarios:**  To solidify understanding, create simple examples:
    * **Input/Output:** Imagine a page with a form field and a specific scroll position. How would this be represented in `ExplodedPageState` and how would it be serialized?
    * **User Errors:** Think about what happens if a user manually modifies a saved page state file or if a website generates invalid state data.
    * **JavaScript Interaction:**  How does `history.pushState()` affect the serialized `state_object`?

9. **Refine and Organize:** Structure the findings logically, starting with the core functionality and then elaborating on the relationships, examples, and potential issues. Use clear headings and bullet points to improve readability.

10. **Review and Validate:**  Double-check the analysis against the code to ensure accuracy and completeness. Consider if any important aspects have been missed. For example, the handling of file uploads within form data is a notable detail.

This systematic approach, combining code skimming, keyword analysis, understanding data structures, tracing logic, and considering practical implications, allows for a comprehensive understanding of the `page_state_serialization.cc` file.
这个文件 `blink/common/page_state/page_state_serialization.cc` 的主要功能是**序列化和反序列化 Web 页面的状态 (PageState)**。  这个状态包含了足够的信息，以便在用户导航历史中前进或后退时，能够恢复页面的外观和行为，例如滚动位置、表单数据、以及其他相关信息。

以下是更详细的功能列表，并结合与 JavaScript、HTML 和 CSS 的关系进行说明：

**核心功能:**

1. **定义 PageState 的数据结构:** 文件中虽然没有直接定义 `PageState` 结构体，但它使用了 `ExplodedPageState` 和 `mojom::PageState`  这两个结构体来表示页面的状态。 `ExplodedPageState` 似乎是一个方便操作的 C++ 结构体，而 `mojom::PageState` 是通过 Mojo 定义的，用于跨进程通信。

2. **序列化 PageState:**  将 `ExplodedPageState` 对象转换为可以存储或传输的二进制数据格式。  这个过程被称为编码或封送 (marshaling)。
   * **使用 `base::Pickle`:** 文件大量使用了 `base::Pickle` 类，这是一个 Chromium 提供的用于序列化基本数据类型和字符串的工具。
   * **支持不同的序列化版本:**  代码中定义了 `kMinVersion` 和 `kCurrentVersion`，这意味着 PageState 的序列化格式可能随着时间推移而改变。旧版本的数据需要能够被新版本解析，反之亦然。代码中有处理不同版本序列化的逻辑。
   * **支持 Mojo 序列化:**  从某个版本开始，引入了基于 Mojo 的序列化方式，使用 `mojom::PageState::Serialize()`。这使得跨进程传递 PageState 更加结构化和高效。

3. **反序列化 PageState:** 将存储或传输的二进制数据转换回 `ExplodedPageState` 对象。这个过程被称为解码或解封 (unmarshaling)。
   * **使用 `base::PickleIterator`:**  与序列化对应，反序列化使用 `base::PickleIterator` 来从 `base::Pickle` 对象中读取数据。
   * **处理不同版本:**  反序列化代码需要根据数据中的版本信息，选择正确的解析方式。
   * **支持 Mojo 反序列化:**  使用 `mojom::PageState::Deserialize()` 来反序列化 Mojo 格式的 PageState。

**与 JavaScript, HTML, CSS 的关系:**

PageState 序列化捕捉了页面的状态，这些状态很多都与 JavaScript, HTML, 和 CSS 的交互有关：

* **JavaScript 的历史 API (`history.pushState`, `history.replaceState`):**
    * **举例说明:**  当 JavaScript 调用 `history.pushState({page: 1}, "title", "?page=1")` 时，传入的 `state` 对象 `{page: 1}`  会被序列化并存储在 PageState 的 `state_object` 字段中。当用户点击浏览器的前进或后退按钮时，反序列化后的 `state_object` 可以被 JavaScript 通过 `window.onpopstate` 事件访问。
    * **假设输入与输出:**
        * **假设输入 (JavaScript):** `history.pushState({scrollPosition: 100}, "Scroll Down", "#scroll");`
        * **假设输出 (序列化的 PageState 中 `state_object`):**  可能是一个包含 `{ "scrollPosition": 100 }` 的 JSON 字符串或其他二进制表示。

* **HTML 表单数据 (`<form>`):**
    * **举例说明:** 用户在一个包含文本输入框的表单中输入了 "hello"，然后导航到另一个页面。PageState 序列化会捕获这个输入值。当用户返回时，反序列化后的 PageState 可以用于恢复表单输入框的值为 "hello"。
    * **假设输入 (HTML 表单):** `<form><input type="text" name="username" value=""></form>`，用户输入 "test"。
    * **假设输出 (序列化的 PageState 中 `document_state`):**  `document_state` 是一个字符串向量，其内容会编码表单的状态，可能包含类似 `["magic_sig", "form_key", "1", "username", "text", "1", "test"]` 的数据（这只是一个简化的示例，实际格式更复杂）。

* **滚动位置:**
    * **举例说明:** 用户滚动页面到某个位置，然后点击链接导航到新页面。PageState 会保存当时的滚动位置。当用户点击返回按钮时，页面会恢复到之前的滚动位置。
    * **假设输入 (用户交互):** 用户将页面垂直滚动到 500px 的位置。
    * **假设输出 (序列化的 PageState 中 `scroll_offset`):**  `scroll_offset` 将会被设置为 `gfx::Point(0, 500)`。

* **页面缩放 (Page Scale Factor):**
    * **举例说明:** 用户在移动设备上双指缩放页面。PageState 可以保存当前的缩放比例，以便在返回时恢复。
    * **假设输入 (用户交互):** 用户将页面放大到 1.5 倍。
    * **假设输出 (序列化的 PageState 中 `page_scale_factor`):** `page_scale_factor` 将会被设置为 `1.5`。

* **可视视口滚动偏移 (Visual Viewport Scroll Offset):**  与页面缩放相关，记录了缩放后的视口在未缩放时的偏移。

* **滚动锚点 (Scroll Anchor):**  PageState 可以保存页面上一个特定元素作为滚动锚点的信息，以便在页面重新加载或返回时，尽量保持用户之前关注的内容在视野内。

* **其他信息:**  PageState 还可能包含其他与页面状态相关的信息，例如：
    * 目标框架 (target frame)
    * Referrer Policy
    * HTTP 请求体 (HTTP Body)，包括上传的文件信息
    * 唯一名称 (unique name)
    * 导航 API 相关信息 (Navigation API Key, State, ID)

**用户或编程常见的使用错误:**

1. **修改序列化格式但不更新版本号:**  如果开发者修改了 PageState 的数据结构或序列化方式，但忘记更新 `kCurrentVersion`，会导致旧版本 Chromium 无法正确解析新的 PageState 数据，或者新版本 Chromium 无法正确解析旧版本的数据，造成前进/后退功能异常或数据丢失。

2. **错误地假设序列化格式的稳定性:**  虽然 Chromium 努力保持向后兼容性，但 PageState 的内部序列化格式仍然可能在不同版本之间发生变化。开发者不应该依赖于特定的序列化细节，而是应该使用 Blink 提供的 API 来操作页面历史状态。

3. **在 JavaScript 中操作历史状态时，传递了无法序列化的对象到 `history.pushState` 或 `history.replaceState`:**  `history.state`  会被序列化，因此传递的对象必须是可序列化的。例如，包含循环引用的对象或某些类型的内置对象可能无法被正确序列化，导致数据丢失或错误。

    * **举例说明:**
        ```javascript
        const obj = {};
        obj.circular = obj;
        history.pushState(obj, "Circular"); // 这可能会导致序列化错误
        ```

4. **在跨域的 iframe 中尝试恢复 PageState:**  由于安全限制，跨域的 iframe 的 PageState 信息可能无法被完全访问或恢复。

5. **过度依赖 PageState 来存储应用程序状态:**  PageState 的主要目的是为了浏览器的前进/后退功能，不应该被用作通用的应用程序状态持久化机制。有更合适的 API 和技术来处理应用程序状态管理。

**总结:**

`blink/common/page_state/page_state_serialization.cc` 是 Blink 引擎中至关重要的一个文件，它负责将 Web 页面的状态转换为可存储和传输的格式，以及将这些格式转换回可用的状态。这使得浏览器的前进和后退功能得以实现，并且与 JavaScript, HTML 和 CSS 的行为紧密相关。 理解其功能和潜在的陷阱对于开发 Web 应用程序和维护 Chromium 浏览器都是很重要的。

### 提示词
```
这是目录为blink/common/page_state/page_state_serialization.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/page_state/page_state_serialization.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "base/containers/span.h"
#include "base/containers/to_vector.h"
#include "base/pickle.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "mojo/public/cpp/base/string16_mojom_traits.h"
#include "mojo/public/cpp/base/time_mojom_traits.h"
#include "mojo/public/cpp/bindings/enum_utils.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "third_party/blink/public/common/loader/http_body_element_type.h"
#include "third_party/blink/public/common/unique_name/unique_name_helper.h"
#include "third_party/blink/public/mojom/page_state/page_state.mojom.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/gfx/geometry/mojom/geometry_mojom_traits.h"
#include "url/mojom/url_gurl_mojom_traits.h"

namespace blink {

namespace {

#if BUILDFLAG(IS_ANDROID)
float g_device_scale_factor_for_testing = 0.0;
#endif

//-----------------------------------------------------------------------------

void AppendDataToRequestBody(
    const scoped_refptr<network::ResourceRequestBody>& request_body,
    const char* data,
    size_t data_length) {
  request_body->AppendBytes(data, data_length);
}

void AppendFileRangeToRequestBody(
    const scoped_refptr<network::ResourceRequestBody>& request_body,
    const std::optional<std::u16string>& file_path,
    int file_start,
    int file_length,
    base::Time file_modification_time) {
  request_body->AppendFileRange(
      file_path ? base::FilePath::FromUTF16Unsafe(*file_path)
                : base::FilePath(),
      static_cast<uint64_t>(file_start), static_cast<uint64_t>(file_length),
      file_modification_time);
}

//----------------------------------------------------------------------------

void AppendReferencedFilesFromHttpBody(
    const std::vector<network::DataElement>& elements,
    std::vector<std::optional<std::u16string>>* referenced_files) {
  for (size_t i = 0; i < elements.size(); ++i) {
    if (elements[i].type() == network::DataElement::Tag::kFile) {
      referenced_files->emplace_back(
          elements[i].As<network::DataElementFile>().path().AsUTF16Unsafe());
    }
  }
}

bool AppendReferencedFilesFromDocumentState(
    const std::vector<std::optional<std::u16string>>& document_state,
    std::vector<std::optional<std::u16string>>* referenced_files) {
  if (document_state.empty())
    return true;

  // This algorithm is adapted from Blink's FormController code.
  // We only care about how that code worked when this code snapshot was taken
  // as this code is only needed for backwards compat.
  //
  // For reference, see FormController::formStatesFromStateVector in
  // third_party/WebKit/Source/core/html/forms/FormController.cpp.

  size_t index = 0;

  if (document_state.size() < 3)
    return false;

  index++;  // Skip over magic signature.
  index++;  // Skip over form key.

  size_t item_count;
  if (!document_state[index] ||
      !base::StringToSizeT(*document_state[index++], &item_count))
    return false;

  while (item_count--) {
    if (index + 1 >= document_state.size())
      return false;

    index++;  // Skip over name.
    const std::optional<std::u16string>& type = document_state[index++];

    if (index >= document_state.size())
      return false;

    size_t value_size;
    if (!document_state[index] ||
        !base::StringToSizeT(*document_state[index++], &value_size))
      return false;

    if (index + value_size > document_state.size() ||
        index + value_size < index)  // Check for overflow.
      return false;

    if (type && base::EqualsASCII(*type, "file")) {
      if (value_size != 2)
        return false;

      referenced_files->emplace_back(document_state[index++]);
      index++;  // Skip over display name.
    } else {
      index += value_size;
    }
  }

  return true;
}

bool RecursivelyAppendReferencedFiles(
    const ExplodedFrameState& frame_state,
    std::vector<std::optional<std::u16string>>* referenced_files) {
  if (frame_state.http_body.request_body) {
    AppendReferencedFilesFromHttpBody(
        *frame_state.http_body.request_body->elements(), referenced_files);
  }

  if (!AppendReferencedFilesFromDocumentState(frame_state.document_state,
                                              referenced_files))
    return false;

  for (size_t i = 0; i < frame_state.children.size(); ++i) {
    if (!RecursivelyAppendReferencedFiles(frame_state.children[i],
                                          referenced_files))
      return false;
  }

  return true;
}

//----------------------------------------------------------------------------

struct SerializeObject {
  SerializeObject() = default;

  explicit SerializeObject(base::span<const uint8_t> data)
      : pickle(base::Pickle::WithUnownedBuffer(data)),
        iter(base::PickleIterator(pickle)) {}

  std::string GetAsString() {
    return std::string(pickle.data_as_char(), pickle.size());
  }

  base::Pickle pickle;
  base::PickleIterator iter;
  int version = 0;
  bool parse_error = false;
};

// IMPORTANT: When making updates to the PageState serialization code, be sure
// to first read
// https://chromium.googlesource.com/chromium/src/+/main/docs/modifying_session_history_serialization.md

// Version ID of serialized format.
// 11: Min version
// 12: Adds support for contains_passwords in HTTP body
// 13: Adds support for URL (FileSystem URL)
// 14: Adds list of referenced files, version written only for first item.
// 15: Removes a bunch of values we defined but never used.
// 16: Switched from blob urls to blob uuids.
// 17: Add a target frame id number.
// 18: Add referrer policy.
// 19: Remove target frame id, which was a bad idea, and original url string,
//         which is no longer used.
// 20: Add visual viewport scroll offset, the offset of the pinched zoomed
//     viewport within the unzoomed main frame.
// 21: Add frame sequence number.
// 22: Add scroll restoration type.
// 23: Remove frame sequence number, there are easier ways.
// 24: Add did save scroll or scale state.
// 25: Limit the length of unique names: https://crbug.com/626202
// 26: Switch to mojo-based serialization.
// 27: Add serialized scroll anchor to FrameState.
// 28: Add initiator origin to FrameState.
// 29: Add navigation API key.
// 30: Add navigation API state.
// 31: Add protect url in navigation API bit.
// 32: Fix assign() for initiator origin.
// 33: Add initiator base url to FrameState.
// NOTE: If the version is -1, then the pickle contains only a URL string.
// See ReadPageState.
//
const int kMinVersion = 11;
// NOTE: When changing the version, please add a backwards compatibility test.
// See PageStateSerializationTest.DumpExpectedPageStateForBackwardsCompat for
// instructions on how to generate the new test case.
const int kCurrentVersion = 33;

// A bunch of convenience functions to write to/read from SerializeObjects.  The
// de-serializers assume the input data will be in the correct format and fall
// back to returning safe defaults when not. These are mostly used by
// legacy(pre-mojo) serialization methods. If you're making changes to the
// PageState serialization format you almost certainly want to add/remove fields
// in page_state.mojom rather than using these methods.

void WriteData(base::span<const uint8_t> data, SerializeObject* obj) {
  obj->pickle.WriteData(data);
}

std::optional<base::span<const uint8_t>> ReadData(SerializeObject* obj) {
  std::optional<base::span<const uint8_t>> result = obj->iter.ReadData();
  if (!result) {
    obj->parse_error = true;
  }
  return result;
}

void WriteInteger(int data, SerializeObject* obj) {
  obj->pickle.WriteInt(data);
}

int ReadInteger(SerializeObject* obj) {
  int tmp;
  if (obj->iter.ReadInt(&tmp))
    return tmp;
  obj->parse_error = true;
  return 0;
}

void WriteInteger64(int64_t data, SerializeObject* obj) {
  obj->pickle.WriteInt64(data);
}

int64_t ReadInteger64(SerializeObject* obj) {
  int64_t tmp = 0;
  if (obj->iter.ReadInt64(&tmp))
    return tmp;
  obj->parse_error = true;
  return 0;
}

void WriteReal(double data, SerializeObject* obj) {
  WriteData(base::byte_span_from_ref(data), obj);
}

double ReadReal(SerializeObject* obj) {
  std::optional<base::span<const uint8_t>> data = ReadData(obj);
  if (data && data->size() == sizeof(double)) {
    double value;
    base::byte_span_from_ref(value).copy_from(
        data.value().first<sizeof(double)>());
    return value;
  }

  obj->parse_error = true;
  return 0.0;
}

void WriteBoolean(bool data, SerializeObject* obj) {
  obj->pickle.WriteInt(data ? 1 : 0);
}

bool ReadBoolean(SerializeObject* obj) {
  bool tmp;
  if (obj->iter.ReadBool(&tmp))
    return tmp;
  obj->parse_error = true;
  return false;
}

GURL ReadGURL(SerializeObject* obj) {
  std::string spec;
  if (obj->iter.ReadString(&spec))
    return GURL(spec);
  obj->parse_error = true;
  return GURL();
}

std::string ReadStdString(SerializeObject* obj) {
  std::string s;
  if (obj->iter.ReadString(&s))
    return s;
  obj->parse_error = true;
  return std::string();
}

// Pickles a std::u16string as <int length>:<char*16 data> tuple>.
void WriteString(const std::u16string& str, SerializeObject* obj) {
  // IMPLEMENTATION WARNING: This is different from Pickle::WriteString16, as
  // that writes the size in 16-bit characters, while this writes the string as
  // data, which writes the size in bytes. This is due to an unfortunate
  // bifurcation where the Pickle version originally wrote a Windows
  // std::wstring, which then turned into std::u16string, while this code
  // originally dealt with WebString(), which then turned into std::u16string.
  obj->pickle.WriteData(base::as_byte_span(str));
}

// If str is a null optional, this simply pickles a length of -1. Otherwise,
// delegates to the std::u16string overload.
void WriteString(const std::optional<std::u16string>& str,
                 SerializeObject* obj) {
  if (!str) {
    obj->pickle.WriteInt(-1);
  } else {
    WriteString(*str, obj);
  }
}

// This reads a serialized std::optional<std::u16string> from obj. If a string
// can't be read, nullptr is returned.
const char16_t* ReadStringNoCopy(SerializeObject* obj, int* num_chars) {
  int length_in_bytes;
  if (!obj->iter.ReadInt(&length_in_bytes)) {
    obj->parse_error = true;
    return nullptr;
  }

  if (length_in_bytes < 0)  // Not an error!  See WriteString(nullopt).
    return nullptr;

  const char* data;
  if (!obj->iter.ReadBytes(&data, static_cast<size_t>(length_in_bytes))) {
    obj->parse_error = true;
    return nullptr;
  }

  if (num_chars)
    *num_chars = length_in_bytes / sizeof(char16_t);
  return reinterpret_cast<const char16_t*>(data);
}

std::optional<std::u16string> ReadString(SerializeObject* obj) {
  int num_chars;
  const char16_t* chars = ReadStringNoCopy(obj, &num_chars);
  std::optional<std::u16string> result;
  if (chars)
    result.emplace(chars, num_chars);
  return result;
}

template <typename T>
void WriteAndValidateVectorSize(const std::vector<T>& v, SerializeObject* obj) {
  CHECK_LT(v.size(), std::numeric_limits<int>::max() / sizeof(T));
  WriteInteger(static_cast<int>(v.size()), obj);
}

size_t ReadAndValidateVectorSize(SerializeObject* obj, size_t element_size) {
  size_t num_elements = static_cast<size_t>(ReadInteger(obj));

  // Ensure that resizing a vector to size num_elements makes sense.
  if (std::numeric_limits<int>::max() / element_size <= num_elements) {
    obj->parse_error = true;
    return 0;
  }

  // Ensure that it is plausible for the pickle to contain num_elements worth
  // of data.
  if (obj->pickle.payload_size() <= num_elements) {
    obj->parse_error = true;
    return 0;
  }

  return num_elements;
}

// Writes a Vector of strings into a SerializeObject for serialization.
void WriteStringVector(const std::vector<std::optional<std::u16string>>& data,
                       SerializeObject* obj) {
  WriteAndValidateVectorSize(data, obj);
  for (size_t i = 0; i < data.size(); ++i) {
    WriteString(data[i], obj);
  }
}

void ReadStringVector(SerializeObject* obj,
                      std::vector<std::optional<std::u16string>>* result) {
  size_t num_elements =
      ReadAndValidateVectorSize(obj, sizeof(std::optional<std::u16string>));

  result->resize(num_elements);
  for (size_t i = 0; i < num_elements; ++i)
    (*result)[i] = ReadString(obj);
}

void WriteResourceRequestBody(const network::ResourceRequestBody& request_body,
                              SerializeObject* obj) {
  WriteAndValidateVectorSize(*request_body.elements(), obj);
  for (const auto& element : *request_body.elements()) {
    switch (element.type()) {
      case network::DataElement::Tag::kBytes: {
        const auto& bytes = element.As<network::DataElementBytes>().bytes();
        WriteInteger(static_cast<int>(HTTPBodyElementType::kTypeData), obj);
        WriteData(bytes, obj);
        break;
      }
      case network::DataElement::Tag::kFile: {
        const auto& file = element.As<network::DataElementFile>();
        WriteInteger(static_cast<int>(HTTPBodyElementType::kTypeFile), obj);
        WriteString(file.path().AsUTF16Unsafe(), obj);
        WriteInteger64(static_cast<int64_t>(file.offset()), obj);
        WriteInteger64(static_cast<int64_t>(file.length()), obj);
        WriteReal(file.expected_modification_time().InSecondsFSinceUnixEpoch(),
                  obj);
        break;
      }
      default:
        NOTREACHED();
    }
  }
  WriteInteger64(request_body.identifier(), obj);
}

void ReadResourceRequestBody(
    SerializeObject* obj,
    const scoped_refptr<network::ResourceRequestBody>& request_body) {
  int num_elements = ReadInteger(obj);
  for (int i = 0; i < num_elements; ++i) {
    HTTPBodyElementType type =
        static_cast<HTTPBodyElementType>(ReadInteger(obj));
    if (type == HTTPBodyElementType::kTypeData) {
      std::optional<base::span<const uint8_t>> data = ReadData(obj);
      if (data) {
        AppendDataToRequestBody(request_body,
                                reinterpret_cast<const char*>(data->data()),
                                data->size());
      }
    } else if (type == HTTPBodyElementType::kTypeFile) {
      std::optional<std::u16string> file_path = ReadString(obj);
      int64_t file_start = ReadInteger64(obj);
      int64_t file_length = ReadInteger64(obj);
      double file_modification_time = ReadReal(obj);
      AppendFileRangeToRequestBody(
          request_body, file_path, file_start, file_length,
          base::Time::FromSecondsSinceUnixEpoch(file_modification_time));
    } else if (type == HTTPBodyElementType::kTypeBlob) {
      // Skip obsolete blob values.
      if (obj->version >= 16) {
        ReadStdString(obj);
      } else {
        ReadGURL(obj);
      }
    }
  }
  request_body->set_identifier(ReadInteger64(obj));
}

void ReadHttpBody(SerializeObject* obj, ExplodedHttpBody* http_body) {
  // An initial boolean indicates if we have an HTTP body.
  if (!ReadBoolean(obj))
    return;

  http_body->request_body = new network::ResourceRequestBody();
  ReadResourceRequestBody(obj, http_body->request_body);

  if (obj->version >= 12)
    http_body->contains_passwords = ReadBoolean(obj);
}

void WriteHttpBody(const ExplodedHttpBody& http_body, SerializeObject* obj) {
  bool is_null = !http_body.request_body;
  WriteBoolean(!is_null, obj);
  if (is_null)
    return;

  WriteResourceRequestBody(*http_body.request_body, obj);
  WriteBoolean(http_body.contains_passwords, obj);
}

// This is only used for versions < 26. Later versions use ReadMojoFrameState.
void ReadLegacyFrameState(
    SerializeObject* obj,
    bool is_top,
    std::vector<UniqueNameHelper::Replacement>* unique_name_replacements,
    ExplodedFrameState* state) {
  if (obj->version < 14 && !is_top)
    ReadInteger(obj);  // Skip over redundant version field.

  state->url_string = ReadString(obj);

  if (obj->version < 19)
    ReadString(obj);  // Skip obsolete original url string field.

  state->target = ReadString(obj);
  if (obj->version < 25 && state->target) {
    state->target = base::UTF8ToUTF16(UniqueNameHelper::UpdateLegacyNameFromV24(
        base::UTF16ToUTF8(*state->target), unique_name_replacements));
  }
  if (obj->version < 15) {
    ReadString(obj);  // Skip obsolete parent field.
    ReadString(obj);  // Skip obsolete title field.
    ReadString(obj);  // Skip obsolete alternate title field.
    ReadReal(obj);    // Skip obsolete visited time field.
  }

  if (obj->version >= 24) {
    state->did_save_scroll_or_scale_state = ReadBoolean(obj);
  } else {
    state->did_save_scroll_or_scale_state = true;
  }

  if (state->did_save_scroll_or_scale_state) {
    int x = ReadInteger(obj);
    int y = ReadInteger(obj);
    state->scroll_offset = gfx::Point(x, y);
  }

  if (obj->version < 15) {
    ReadBoolean(obj);  // Skip obsolete target item flag.
    ReadInteger(obj);  // Skip obsolete visit count field.
  }
  state->referrer = ReadString(obj);

  ReadStringVector(obj, &state->document_state);

  if (state->did_save_scroll_or_scale_state)
    state->page_scale_factor = ReadReal(obj);

  state->item_sequence_number = ReadInteger64(obj);
  state->document_sequence_number = ReadInteger64(obj);
  if (obj->version >= 21 && obj->version < 23)
    ReadInteger64(obj);  // Skip obsolete frame sequence number.

  if (obj->version >= 17 && obj->version < 19)
    ReadInteger64(obj);  // Skip obsolete target frame id number.

  if (obj->version >= 18) {
    state->referrer_policy =
        mojo::ConvertIntToMojoEnum<network::mojom::ReferrerPolicy>(
            ReadInteger(obj))
            .value_or(network::mojom::ReferrerPolicy::kDefault);
  }

  if (obj->version >= 20 && state->did_save_scroll_or_scale_state) {
    double x = ReadReal(obj);
    double y = ReadReal(obj);
    state->visual_viewport_scroll_offset = gfx::PointF(x, y);
  } else {
    state->visual_viewport_scroll_offset = gfx::PointF(-1, -1);
  }

  if (obj->version >= 22) {
    state->scroll_restoration_type =
        static_cast<mojom::ScrollRestorationType>(ReadInteger(obj));
  }

  bool has_state_object = ReadBoolean(obj);
  if (has_state_object)
    state->state_object = ReadString(obj);

  ReadHttpBody(obj, &state->http_body);

  // NOTE: It is a quirk of the format that we still have to read the
  // http_content_type field when the HTTP body is null.  That's why this code
  // is here instead of inside ReadHttpBody.
  state->http_body.http_content_type = ReadString(obj);

  if (obj->version < 14)
    ReadString(obj);  // Skip unused referrer string.

#if BUILDFLAG(IS_ANDROID)
  if (obj->version == 11) {
    // Now-unused values that shipped in this version of Chrome for Android when
    // it was on a private branch.
    ReadReal(obj);
    ReadBoolean(obj);

    // In this version, page_scale_factor included device_scale_factor and
    // scroll offsets were premultiplied by pageScaleFactor.
    if (state->page_scale_factor) {
      float device_scale_factor = g_device_scale_factor_for_testing;
      if (!device_scale_factor) {
        device_scale_factor = display::Screen::GetScreen()
                                  ->GetPrimaryDisplay()
                                  .device_scale_factor();
      }
      state->scroll_offset =
          gfx::Point(state->scroll_offset.x() / state->page_scale_factor,
                     state->scroll_offset.y() / state->page_scale_factor);
      state->page_scale_factor /= device_scale_factor;
    }
  }
#endif

  // Subitems
  size_t num_children =
      ReadAndValidateVectorSize(obj, sizeof(ExplodedFrameState));
  state->children.resize(num_children);
  for (size_t i = 0; i < num_children; ++i) {
    ReadLegacyFrameState(obj, false, unique_name_replacements,
                         &state->children[i]);
  }
}

// Writes the ExplodedFrameState data into the SerializeObject object for
// serialization. This uses the custom, legacy format, and its implementation
// should remain frozen in order to preserve this format.
// TODO(pnoland, dcheng) Move the legacy write methods into a test-only helper.
void WriteLegacyFrameState(const ExplodedFrameState& state,
                           SerializeObject* obj,
                           bool is_top) {
  // WARNING: This data may be persisted for later use. As such, care must be
  // taken when changing the serialized format. If a new field needs to be
  // written, only adding at the end will make it easier to deal with loading
  // older versions. Similarly, this should NOT save fields with sensitive
  // data, such as password fields.

  WriteString(state.url_string, obj);
  WriteString(state.target, obj);
  WriteBoolean(state.did_save_scroll_or_scale_state, obj);

  if (state.did_save_scroll_or_scale_state) {
    WriteInteger(state.scroll_offset.x(), obj);
    WriteInteger(state.scroll_offset.y(), obj);
  }

  WriteString(state.referrer, obj);

  WriteStringVector(state.document_state, obj);

  if (state.did_save_scroll_or_scale_state)
    WriteReal(state.page_scale_factor, obj);

  WriteInteger64(state.item_sequence_number, obj);
  WriteInteger64(state.document_sequence_number, obj);
  WriteInteger(static_cast<int>(state.referrer_policy), obj);

  if (state.did_save_scroll_or_scale_state) {
    WriteReal(state.visual_viewport_scroll_offset.x(), obj);
    WriteReal(state.visual_viewport_scroll_offset.y(), obj);
  }

  WriteInteger(static_cast<int>(state.scroll_restoration_type), obj);

  bool has_state_object = state.state_object.has_value();
  WriteBoolean(has_state_object, obj);
  if (has_state_object)
    WriteString(*state.state_object, obj);

  WriteHttpBody(state.http_body, obj);

  // NOTE: It is a quirk of the format that we still have to write the
  // http_content_type field when the HTTP body is null.  That's why this code
  // is here instead of inside WriteHttpBody.
  WriteString(state.http_body.http_content_type, obj);

  // Subitems
  const std::vector<ExplodedFrameState>& children = state.children;
  WriteAndValidateVectorSize(children, obj);
  for (size_t i = 0; i < children.size(); ++i)
    WriteLegacyFrameState(children[i], obj, false);
}

void WriteLegacyPageState(const ExplodedPageState& state,
                          SerializeObject* obj) {
  WriteInteger(obj->version, obj);
  WriteStringVector(state.referenced_files, obj);
  WriteLegacyFrameState(state.top, obj, true);
}

// Legacy read/write functions above this line. Don't change these.
//-----------------------------------------------------------------------------
// "Modern" read/write functions start here. These are probably what you want.

void WriteResourceRequestBody(const network::ResourceRequestBody& request_body,
                              mojom::RequestBody* mojo_body) {
  for (const auto& element : *request_body.elements()) {
    mojom::ElementPtr data_element;
    switch (element.type()) {
      case network::DataElement::Tag::kBytes: {
        const auto& bytes = element.As<network::DataElementBytes>().bytes();
        data_element = mojom::Element::NewBytes(base::ToVector(bytes));
        break;
      }
      case network::DataElement::Tag::kFile: {
        const auto& element_file = element.As<network::DataElementFile>();
        mojom::FilePtr file = mojom::File::New(
            element_file.path().AsUTF16Unsafe(), element_file.offset(),
            element_file.length(), element_file.expected_modification_time());
        data_element = mojom::Element::NewFile(std::move(file));
        break;
      }
      case network::DataElement::Tag::kDataPipe:
        NOTIMPLEMENTED();
        continue;
      case network::DataElement::Tag::kChunkedDataPipe:
        NOTREACHED();
    }
    mojo_body->elements.push_back(std::move(data_element));
  }
  mojo_body->identifier = request_body.identifier();
}

void ReadResourceRequestBody(
    mojom::RequestBody* mojo_body,
    const scoped_refptr<network::ResourceRequestBody>& request_body) {
  for (const auto& element : mojo_body->elements) {
    mojom::Element::Tag tag = element->which();
    switch (tag) {
      case mojom::Element::Tag::kBytes:
        AppendDataToRequestBody(
            request_body,
            reinterpret_cast<const char*>(element->get_bytes().data()),
            element->get_bytes().size());
        break;
      case mojom::Element::Tag::kFile: {
        mojom::File* file = element->get_file().get();
        AppendFileRangeToRequestBody(request_body, file->path, file->offset,
                                     file->length, file->modification_time);
        break;
      }
      case mojom::Element::Tag::kBlobUuid:
        // No longer supported.
        break;
      case mojom::Element::Tag::kDeprecatedFileSystemFile:
        // No longer supported.
        break;
    }
  }
  request_body->set_identifier(mojo_body->identifier);
}

void WriteHttpBody(const ExplodedHttpBody& http_body,
                   mojom::HttpBody* mojo_body) {
  if (http_body.request_body) {
    mojo_body->request_body = mojom::RequestBody::New();
    mojo_body->contains_passwords = http_body.contains_passwords;
    mojo_body->http_content_type = http_body.http_content_type;
    WriteResourceRequestBody(*http_body.request_body,
                             mojo_body->request_body.get());
  }
}

void ReadHttpBody(mojom::HttpBody* mojo_body, ExplodedHttpBody* http_body) {
  http_body->contains_passwords = mojo_body->contains_passwords;
  http_body->http_content_type = mojo_body->http_content_type;
  if (mojo_body->request_body) {
    http_body->request_body =
        base::MakeRefCounted<network::ResourceRequestBody>();
    ReadResourceRequestBody(mojo_body->request_body.get(),
                            http_body->request_body);
  }
}

// Do not depend on feature state when writing data to frame, so that the
// contents of persisted history do not depend on whether a feature is enabled
// or not.
void WriteMojoFrameState(const ExplodedFrameState& state,
                         mojom::FrameState* frame) {
  frame->url_string = state.url_string;
  frame->referrer = state.referrer;
  if (state.initiator_origin.has_value())
    frame->initiator_origin = state.initiator_origin.value().Serialize();
  frame->initiator_base_url_string = state.initiator_base_url_string;
  frame->target = state.target;
  frame->state_object = state.state_object;

  for (const auto& s : state.document_state) {
    frame->document_state.push_back(s);
  }

  frame->scroll_restoration_type =
      static_cast<mojom::ScrollRestorationType>(state.scroll_restoration_type);

  if (state.did_save_scroll_or_scale_state) {
    frame->view_state = mojom::ViewState::New();
    frame->view_state->scroll_offset = state.scroll_offset;
    frame->view_state->visual_viewport_scroll_offset =
        state.visual_viewport_scroll_offset;
    frame->view_state->page_scale_factor = state.page_scale_factor;
    // We discard all scroll anchor data if the selector is over the length
    // limit. We don't want to bloat the size of FrameState, and the other
    // fields are useless without the selector.
    if (state.scroll_anchor_selector && state.scroll_anchor_selector->length() <
                                            kMaxScrollAnchorSelectorLength) {
      frame->view_state->scroll_anchor_selector = state.scroll_anchor_selector;
      frame->view_state->scroll_anchor_offset = state.scroll_anchor_offset;
      frame->view_state->scroll_anchor_simhash = state.scroll_anchor_simhash;
    }
  }

  frame->item_sequence_number = state.item_sequence_number;
  frame->document_sequence_number = state.document_sequence_number;

  frame->referrer_policy = state.referrer_policy;

  frame->http_body = mojom::HttpBody::New();
  WriteHttpBody(state.http_body, frame->http_body.get());

  frame->navigation_api_key = state.navigation_api_key;
  frame->navigation_api_id = state.navigation_api_id;
  frame->navigation_api_state = state.navigation_api_state;
  frame->protect_url_in_navigation_api = state.protect_url_in_navigation_api;

  // Subitems
  const std::vector<ExplodedFrameState>& children = state.children;
  for (const auto& child : children) {
    mojom::FrameStatePtr child_frame = mojom::FrameState::New();
    WriteMojoFrameState(child, child_frame.get());
    frame->children.push_back(std::move(child_frame));
  }
}

// This is used for versions >= 26.
void ReadMojoFrameState(mojom::FrameState* frame, ExplodedFrameState* state) {
  state->url_string = frame->url_string;
  state->referrer = frame->referrer;
  if (frame->initiator_origin.has_value()) {
    state->initiator_origin =
        url::Origin::Create(GURL(frame->initiator_origin.value()));
  }
  state->initiator_base_url_string = frame->initiator_base_url_string;

  state->target = frame->target;
  state->state_object = frame->state_object;

  for (const auto& s : frame->document_state) {
    state->document_state.push_back(s);
  }

  state->scroll_restoration_type =
      static_cast<mojom::ScrollRestorationType>(frame->scroll_restoration_type);

  if (frame->view_state) {
    state->did_save_scroll_or_scale_state = true;
    state->visual_viewport_scroll_offset =
        frame->view_state->visual_viewport_scroll_offset;
    state->scroll_offset = frame->view_state->scroll_offset;
    state->page_scale_factor = frame->view_state->page_scale_factor;
  }

  if (frame->view_state) {
    state->scroll_anchor_selector = frame->view_state->scroll_anchor_selector;
    state->scroll_anchor_offset =
        frame->view_state->scroll_anchor_offset.value_or(gfx::PointF());
    state->scroll_anchor_simhash = frame->view_state->scroll_anchor_simhash;
  }

  state->item_sequence_number = frame->item_sequence_number;
  state->document_sequence_number = frame->document_sequence_number;

  state->referrer_policy = frame->referrer_policy;
  if (frame->http_body) {
    ReadHttpBody(frame->http_body.get(), &state->http_body);
  } else {
    state->http_body.request_body = nullptr;
  }

  state->navigation_api_key = frame->navigation_api_key;
  state->navigation_api_id = frame->navigation_api_id;
  state->navigation_api_state = frame->navigation_api_state;
  state->protect_url_in_navigation_api = frame->protect_url_in_navigation_api;

  state->children.resize(frame->children.size());
  int i = 0;
  for (const auto& child : frame->children)
    ReadMojoFrameState(child.get(), &state->children[i++]);
}

void ReadMojoPageState(SerializeObject* obj, ExplodedPageState* state) {
  std::optional<base::span<const uint8_t>> data = ReadData(obj);
  if (obj->parse_error) {
    return;
  }

  mojom::PageStatePtr page;
  obj->parse_error =
      !(mojom::PageState::Deserialize(data->data(), data->size(), &page));
  if (obj->parse_error) {
    return;
  }

  for (const auto& referenced_file : page->referenced_files) {
    state->referenced_files.push_back(referenced_file);
  }

  ReadMojoFrameState(page->top.get(), &state->top);

  state->referenced_files.erase(std::unique(state->referenced_files.begin(),
                                            state->referenced_files.end()),
                                state->referenced_files.end());
}

void WriteMojoPageState(const ExplodedPageState& state, SerializeObject* obj) {
  WriteInteger(obj->version, obj);

  mojom::PageStatePtr page = mojom::PageState::New();
  for (const auto& referenced_file : state.referenced_files) {
    page->referenced_files.push_back(referenced_file.value());
  }

  page->top = mojom::FrameState::New();
  WriteMojoFrameState(state.top, page->top.get());

  std::vector<uint8_t> page_bytes = mojom::PageState::Serialize(&page);
  obj->pickle.WriteData(page_bytes);
}

void ReadPageState(SerializeObject* obj, ExplodedPageState* state) {
  obj->version = ReadInteger(obj);

  if (obj->version == -1) {
    GURL url = ReadGURL(obj);
    // NOTE: GURL::possibly_invalid_spec() always returns valid UTF-8.
    state->top.url_string = base::UTF8ToUTF16(url.possibly_invalid_spec());
    return;
  }

  if (obj->version > kCurrentVersion || obj->version < kMinVersion) {
    obj->parse_error = true;
    return;
  }

  if (obj->version >= 26) {
    ReadMojoPageState(obj, state);
    return;
  }

  if (obj->version >= 14)
    ReadStringVector(obj, &state->referenced_files);

  std::vector<UniqueNameHelper::Replacement> unique_name_replacements;
  ReadLegacyFrameState(obj, true, &unique_name_replacements, &state->top);

  if (obj->version < 14)
    RecursivelyAppendReferencedFiles(state->top, &state->referenced_files);

  // De-dupe
  state->referenced_files.erase(std::unique(state->referenced_files.begin(),
                                            state->referenced_files.end()),
                                state->referenced_files.end());
}

}  // namespace

ExplodedHttpBody::ExplodedHttpBody() : contains_passwords(false) {}

ExplodedHttpBody::~ExplodedHttpBody() {}

ExplodedFrameState::ExplodedFrameState() = default;

ExplodedFrameState::ExplodedFrameState(const ExplodedFrameState& other) {
  assign(other);
}

ExplodedFrameState::~ExplodedFrameState() {}

void ExplodedFrameState::operator=(const ExplodedFrameState& other) {
  if (&other != this)
    assign(other);
}

// All members of ExplodedFrameState should be copied.
void ExplodedFrameState::assign(const ExplodedFrameState& other) {
  url_string = other.url_string;
  referrer = other.referrer;
  initiator_origin = other.initiator_origin;
  initiator_base_url_string = other.initiator_base_url_string;
  target = other.target;
  state_object = other.state_object;
  document_state = other.document_state;
  scroll_restoration_type = other.scroll_restoration_type;
  did_save_scroll_or_scale_state = other.did_save_scroll_or_scale_state;
  visual_viewport_scroll_offset = other.visual_viewport_scroll_offset;
  scroll_offset = other.scroll_offset;
  item_sequence_number = other.item_sequence_number;
  document_sequence_number = other.document_sequence_number;
  page_scale_factor = other.page_scale_factor;
  referrer_policy = other.referrer_policy;
  http_body = other.http_body;
  scroll_anchor_selector = other.scroll_anchor_selector;
  scroll_anchor_offset = other.scroll_anchor_offset;
  scroll_anchor_simhash = other.scroll_anchor_simhash;
  navigation_api_key = other.navigation_api_key;
  navigation_api_id = other.navigation_api_id;
  navigation_api_state = other.navigation_api_state;
  protect_url_in_navigation_api = other.protect_url_in_navigation_api;
  children = other.children;
}

ExplodedPageState::ExplodedPageState() {}

ExplodedPageState::~ExplodedPageState() {}

int DecodePageStateInternal(const std::string& encoded,
                            ExplodedPageState* exploded) {
  *exploded = ExplodedPageState();

  if (encoded.empty())
    return true;

  SerializeObject obj(base::as_byte_span(encoded));
  ReadPageState(&obj, exploded);
  return obj.parse_error ? -1 : obj.version;
}

bool DecodePageState(const std::string& encoded, ExplodedPageState* exploded) {
  return DecodePageStateInternal(encoded, exploded) != -1;
}

int DecodePageStateForTesting(const std::string& encoded,
                              ExplodedPageState* exploded) {
  return DecodePageStateInternal(encoded, exploded);
}

void EncodePageState(const ExplodedPageState& exploded, std::string* encoded) {
  SerializeObject obj;
  obj.version = kCurrentVersion;
  WriteMojoPageState(exploded, &obj);
  *encoded = obj.GetAsString();
  DCHECK(!encoded->empty());
}

void LegacyEncodePageStateForTesting(const ExplodedPageState& exploded,
                                     int version,
                                     std::string* encoded) {
  SerializeObject obj;
  obj.version = version;
  WriteLegacyPageState(exploded, &obj);
  *encoded = obj.GetAsString();
}

#if BUILDFLAG(IS_ANDROID)
bool DecodePageStateWithDeviceScaleFactorForTesting(
    const std::string& encoded,
    float device_scale_factor,
    ExplodedPageState* exploded) {
  g_device_scale_factor_for_testing = device_scale_factor;
  bool rv = DecodePageState(encoded, exploded);
  g_device_scale_factor_for_testing = 0.0;
  return rv;
}

scoped_refptr<network::ResourceRequestBody> DecodeResourceRequestBody(
    base::span<const uint8_t> data) {
  scoped_refptr<network::ResourceRequestBody> result =
      new network::ResourceRequestBody();
  SerializeObject obj(data);
  ReadResourceRequestBody(&obj, result);
  // Please see the EncodeResourceRequestBody() function below for information
  // about why the contains_sensitive_info() field is being explicitly
  // deserialized.
  result->set_contains_sensitive_info(ReadBoolean(&obj));
  return obj.parse_error ? nullptr : result;
}

std::string EncodeResourceRequestBody(
    const network::ResourceRequestBody& resource_request_body) {
  SerializeObject obj;
  obj.version = 25;
  WriteResourceRequestBody(resource_request_body, &obj);
  // EncodeResourceRequestBody() is different from WriteResourceRequestBody()
  // because it covers additional data (e.g.|contains_sensitive_info|) which
  // is marshaled between native code and java. WriteResourceRequestBody()
  // serializes data which needs to be saved out to disk.
  WriteBoolean(resource_request_body.contains_sensitive_info(), &obj);
  return obj.GetAsString();
}

#endif

}  // namespace blink
```