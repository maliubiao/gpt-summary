Response:
Let's break down the thought process to analyze the provided C++ code.

**1. Understanding the Goal:**

The request asks for an analysis of the `spdy_protocol.cc` file, focusing on its functionality, relationship with JavaScript (if any), logical reasoning with examples, common user/programming errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and Core Functionality Identification:**

The first step is to quickly scan the code and identify the major components and their purposes. Keywords like "Spdy", "HTTP2", "Frame", "Settings", "Error", and various frame types (DATA, HEADERS, etc.) immediately stand out. The `#include` statements confirm this is related to networking, specifically the SPDY and HTTP/2 protocols.

* **Key Data Structures:**  Notice the `SpdyFrameType`, `SpdySettingsId`, `SpdyErrorCode` enums/typedefs. These represent the fundamental building blocks of the protocols.
* **Frame Representation:**  Classes like `SpdyDataIR`, `SpdyHeadersIR`, `SpdySettingsIR`, etc., suggest this file defines data structures for representing different types of HTTP/2 frames in memory. The "IR" suffix likely stands for "Intermediate Representation".
* **Serialization and Deserialization Hints:** Functions like `SerializeFrameType`, `ParseFrameType`, `ParseSettingsId` indicate this code is involved in converting between in-memory representations and the wire format.
* **Utility Functions:** Functions like `ClampSpdy3Priority`, `ClampHttp2Weight`, and the priority conversion functions suggest utility functions for handling protocol-specific details and conversions.
* **Error Handling:** The `SpdyErrorCode` enum and `ErrorCodeToString` function clearly relate to error handling within the protocol implementation.
* **Constants:** The `kHttp2ConnectionHeaderPrefix` and `kHttp2Npn` constants are important for protocol negotiation and identification.

**3. Deeper Dive into Key Sections:**

Now, examine specific sections for more detailed understanding:

* **Frame Type Handling:** The `IsDefinedFrameType`, `ParseFrameType`, `SerializeFrameType`, and `FrameTypeToString` functions are crucial for working with HTTP/2 frame types. The `IsValidHTTP2FrameStreamId` function clarifies rules about which frame types are associated with specific stream IDs.
* **Settings Handling:** The `ParseSettingsId` and `SettingsIdToString` functions handle the different HTTP/2 settings parameters.
* **Error Code Handling:** The `ParseErrorCode` and `ErrorCodeToString` functions are essential for understanding and reporting errors.
* **Frame IR Classes:** Analyze the base classes (`SpdyFrameIR`, `SpdyFrameWithFinIR`, `SpdyFrameWithHeaderBlockIR`) and the derived classes for each frame type. Note the common methods like `Visit`, `frame_type`, and `size`. The `Visit` pattern suggests a visitor pattern is used for processing frames.
* **Size Calculation:** Pay attention to how the `size()` method is implemented for each frame type. This is critical for correctly formatting and parsing frames.
* **Priority Handling:** The functions related to priority mapping between SPDY3 and HTTP/2 are important for understanding how request prioritization is handled.

**4. Addressing the Specific Questions:**

* **Functionality:**  Summarize the findings from the code scan and deeper dive, focusing on the core purpose of defining data structures and utilities for the HTTP/2 protocol.
* **Relationship with JavaScript:**  This requires considering how web browsers and Node.js (the common JavaScript runtime environments) interact with network protocols. The key is that this C++ code is *part of the browser's implementation*. JavaScript running in the browser uses APIs (like `fetch` or `XMLHttpRequest`) that eventually rely on this underlying network stack. Provide concrete examples of JavaScript actions that trigger HTTP/2 communication.
* **Logical Reasoning (Assumptions and Outputs):** Select a simple function (like `ClampHttp2Weight` or `Spdy3PriorityToHttp2Weight`) and provide example inputs and expected outputs. This demonstrates understanding of the function's behavior. Clearly state the assumptions.
* **User/Programming Errors:** Think about common mistakes when dealing with HTTP/2 concepts. Invalid priority values, incorrect frame sizes, or misusing stream IDs are good examples. Relate these errors to the functions in the code that would enforce these rules (e.g., the clamping functions, the `IsValidHTTP2FrameStreamId` function).
* **Debugging Scenario:**  Consider a common web development problem that might lead to investigating the network layer. A slow loading resource is a good example. Trace the steps a developer would take using browser developer tools, explaining how the network tab and potentially deeper debugging tools could lead them to suspect HTTP/2 issues and potentially the code in question.

**5. Structuring the Answer:**

Organize the information logically, using clear headings and bullet points. Start with a concise summary of the file's purpose. Address each part of the request (functionality, JavaScript relation, logic, errors, debugging) separately.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code directly interacts with JavaScript.
* **Correction:** Realize that this is a lower-level C++ implementation within the browser. JavaScript interacts with *APIs* that eventually use this code. Focus on the indirect relationship.
* **Initial thought:**  List *all* the functions.
* **Refinement:** Focus on the *key* functions and concepts that illustrate the file's purpose. Don't just list everything.
* **Initial thought:**  Provide very complex logical examples.
* **Refinement:** Keep the logical examples simple and easy to understand, focusing on illustrating the function's purpose.

By following these steps, analyzing the code snippets, and iteratively refining the understanding, we can construct a comprehensive and accurate answer to the request.
这个文件 `net/third_party/quiche/src/quiche/http2/core/spdy_protocol.cc` 是 Chromium 网络栈中 QUIC 库的一部分，专门负责处理 HTTP/2 和 SPDY 协议的核心定义和辅助函数。 它的主要功能是：

**1. 定义 HTTP/2 和 SPDY 协议的常量和数据结构:**

* **帧类型 (Frame Types):** 定义了 HTTP/2 协议中各种帧的类型，如 `DATA` (数据), `HEADERS` (头部), `SETTINGS` (设置), `PING` (心跳), `GOAWAY` (关闭连接) 等。通过枚举 `SpdyFrameType` 来实现。
* **设置 ID (Settings IDs):** 定义了 HTTP/2 协议中 `SETTINGS` 帧可以携带的各种设置项的 ID，例如 `SETTINGS_MAX_CONCURRENT_STREAMS` (最大并发流数), `SETTINGS_INITIAL_WINDOW_SIZE` (初始窗口大小) 等。通过枚举 `SpdyKnownSettingsId` 来实现。
* **错误码 (Error Codes):** 定义了 HTTP/2 和 SPDY 协议中可以出现的各种错误码，例如 `ERROR_CODE_PROTOCOL_ERROR` (协议错误), `ERROR_CODE_INTERNAL_ERROR` (内部错误) 等。通过枚举 `SpdyErrorCode` 来实现。
* **优先级 (Priority):**  定义了 SPDY3 和 HTTP/2 的优先级表示方式，并提供了两者之间的转换函数。
* **帧结构体 (Frame Structures):** 定义了表示各种 HTTP/2 帧的 C++ 类，例如 `SpdyDataIR`, `SpdyHeadersIR`, `SpdySettingsIR` 等。这些类封装了帧的数据和元信息。  "IR" 可能代表 "Intermediate Representation"。
* **其他常量:**  定义了诸如 HTTP/2 连接头前缀 (`kHttp2ConnectionHeaderPrefix`),  NPN 协商字符串 (`kHttp2Npn`),  标准头部字段名称 (`kHttp2AuthorityHeader`, `kHttp2MethodHeader` 等) 等常量。

**2. 提供用于操作 HTTP/2 和 SPDY 协议的辅助函数:**

* **类型转换和校验:**  提供了在整数和枚举类型之间进行转换，并校验其有效性的函数，例如 `ParseFrameType`, `SerializeFrameType`, `ParseSettingsId`, `ParseErrorCode`, `IsValidHTTP2FrameStreamId`。
* **字符串转换:** 提供了将枚举值转换为可读字符串的函数，例如 `FrameTypeToString`, `SettingsIdToString`, `ErrorCodeToString`, `WriteSchedulerTypeToString`。
* **优先级处理:**  提供了 `ClampSpdy3Priority` 和 `ClampHttp2Weight` 来限制优先级的取值范围，并提供了 `Spdy3PriorityToHttp2Weight` 和 `Http2WeightToSpdy3Priority` 在不同版本协议之间转换优先级表示方式。
* **帧大小计算:** 提供了计算各种帧大小的函数，例如 `size()` 方法在各个帧结构体中实现，以及 `GetNumberRequiredContinuationFrames` 计算需要多少个 `CONTINUATION` 帧来发送较大的头部块。

**3. 定义了帧访问者模式 (Visitor Pattern) 的接口:**

* `SpdyFrameVisitor`:  定义了访问各种帧类型的接口方法，例如 `VisitData`, `VisitHeaders`, `VisitSettings` 等。这允许以统一的方式处理不同类型的帧。

**与 JavaScript 功能的关系：**

该 C++ 代码本身不直接运行在 JavaScript 环境中。 然而，它是 Chromium 浏览器网络栈的核心组成部分。 当 JavaScript 代码通过浏览器提供的 Web API (如 `fetch` 或 `XMLHttpRequest`) 发起 HTTP/2 请求时，最终会调用到这个 C++ 代码来构建、解析和处理 HTTP/2 帧。

**举例说明：**

假设 JavaScript 代码发起一个简单的 HTTP/2 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

1. **JavaScript `fetch` 调用:**  JavaScript 的 `fetch` API 被调用。
2. **浏览器网络栈处理:** 浏览器内部的网络栈开始处理这个请求。
3. **HTTP/2 连接建立 (如果需要):**  如果与 `example.com` 的连接使用 HTTP/2，则会复用已有的连接或者建立新的连接。
4. **构造 HEADERS 帧:**  `spdy_protocol.cc` 中的 `SpdyHeadersIR` 类会被用来构造一个 HTTP/2 `HEADERS` 帧，其中包含了请求的方法 (`:method: GET`), 路径 (`:path: /data`), 主机 (`:authority: example.com`), 协议 (`:scheme: https`) 等头部信息。
5. **发送 HEADERS 帧:**  这个 `HEADERS` 帧会被序列化并通过底层的网络传输层发送到服务器。
6. **接收 DATA 帧:**  服务器返回数据，浏览器网络栈会接收包含数据的 HTTP/2 `DATA` 帧。
7. **解析 DATA 帧:** `spdy_protocol.cc` 中的相关代码会解析收到的 `DATA` 帧，提取出有效的数据负载。
8. **将数据传递给 JavaScript:**  最终，解析出的数据会通过 `fetch` API 的 Promise 返回给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个表示 HTTP/2 优先级（SPDY3 格式）的值 `priority = 2`。

**函数:** `Spdy3PriorityToHttp2Weight(priority)`

**逻辑:** 该函数将 SPDY3 的优先级映射到 HTTP/2 的权重值。SPDY3 的优先级值越小，优先级越高。HTTP/2 的权重值越大，优先级越高。

**输出:** 根据代码中的转换公式 `const float kSteps = 255.9f / 7.f; return static_cast<int>(kSteps * (7.f - priority)) + 1;`，当 `priority = 2` 时，输出的 HTTP/2 权重值将接近 `255.9f / 7.f * (7 - 2) + 1 = 36.55 * 5 + 1 = 183.75 + 1 = 184`。因此，输出大约为 `184`。

**用户或编程常见的使用错误 (举例说明):**

1. **传递无效的优先级值:** 用户或程序员可能会尝试使用超出有效范围的优先级值。例如，对于 SPDY3，有效的优先级范围是 `kV3HighestPriority` (0) 到 `kV3LowestPriority` (7)。 如果传递了 `priority = 10`，`ClampSpdy3Priority` 函数会将其限制为 `kV3LowestPriority` (7)，并可能触发 `QUICHE_BUG` 日志。

   ```c++
   SpdyPriority invalid_priority = 10;
   SpdyPriority clamped_priority = ClampSpdy3Priority(invalid_priority);
   // clamped_priority 的值为 7，并且控制台可能会输出 "Invalid priority: 10" 的错误日志。
   ```

2. **使用错误的帧类型 ID:**  在处理接收到的数据时，程序员可能会错误地解释帧类型 ID。例如，将一个 `DATA` 帧的类型 ID 误认为是 `HEADERS` 帧的类型 ID。这将导致解析错误，因为不同类型的帧具有不同的结构。`ParseFrameType` 函数会尝试将 `uint8_t` 转换为 `SpdyFrameType`，如果 `frame_type_field` 的值不是定义的类型，则会触发 `QUICHE_BUG_IF` 断言。

   ```c++
   uint8_t incorrect_frame_type_id = 0x01; // 假设这是 HEADERS 帧的 ID，但实际是其他类型的
   SpdyFrameType frame_type = ParseFrameType(incorrect_frame_type_id); // 如果 0x01 不是定义的帧类型，这里会触发断言。
   ```

3. **构建无效的帧结构:**  在手动构建 HTTP/2 帧时，程序员可能会设置不正确的标志位或字段值。例如，为一个流 ID 为 0 的 `DATA` 帧设置了 `END_STREAM` 标志，这是不符合 HTTP/2 协议规范的。`IsValidHTTP2FrameStreamId` 函数会检查帧类型和流 ID 的组合是否有效，并在不符合规范时返回 `false`。

   ```c++
   SpdyDataIR data_frame(0); // 流 ID 为 0 的 DATA 帧是无效的
   data_frame.set_fin(true); // 设置 END_STREAM 标志
   // 后续处理可能会出错，因为 DATA 帧不应该关联到流 ID 0。
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问一个网站，该网站使用 HTTP/2 协议。  如果用户遇到以下问题，可能会触发对 `spdy_protocol.cc` 代码的检查：

1. **连接建立失败或异常断开:**  如果浏览器与服务器建立 HTTP/2 连接时失败，或者连接突然断开，开发者可能会查看网络日志，发现与 HTTP/2 相关的错误码。这些错误码是在 `spdy_protocol.cc` 中定义的。
2. **请求超时或加载缓慢:** 如果网页上的某些资源加载缓慢或者超时，开发者可能会使用浏览器的开发者工具查看网络请求的详细信息。  他们可能会看到与 HTTP/2 帧相关的事件，例如发送和接收的 `HEADERS` 帧、`DATA` 帧等。如果怀疑是 HTTP/2 协议层的问题，可能会查看 Chromium 的网络源码，特别是处理帧解析和生成的代码，这就会涉及到 `spdy_protocol.cc`。
3. **服务端返回错误状态码:**  如果服务器返回了非 200 的 HTTP 状态码，并且怀疑是 HTTP/2 协议层的问题导致的，开发者可能会检查与错误码处理相关的代码。 `ErrorCodeToString` 函数可以帮助将数字错误码转换为可读的字符串。
4. **浏览器控制台输出与 HTTP/2 相关的错误信息:**  Chromium 可能会在控制台输出与 HTTP/2 协议相关的错误或警告信息。这些信息可能直接或间接地指向 `spdy_protocol.cc` 中定义的常量或逻辑。

**调试线索:**

* **网络抓包工具 (如 Wireshark):**  使用网络抓包工具可以捕获浏览器与服务器之间的 HTTP/2 数据包，查看实际发送和接收的帧结构和内容。这可以帮助开发者验证浏览器是否按照预期构建和解析帧。
* **Chromium 的 net-internals 工具:**  Chromium 浏览器内置了 `net-internals` 工具 (可以在浏览器地址栏输入 `chrome://net-internals/` 打开)。该工具提供了详细的网络事件日志，包括 HTTP/2 连接的建立、帧的发送和接收、错误信息等。通过分析这些日志，开发者可以定位到可能出现问题的 HTTP/2 交互环节。
* **Chromium 源码调试:**  如果开发者需要深入了解问题，可以使用 Chromium 的源码进行调试。他们可以在 `spdy_protocol.cc` 中的关键函数上设置断点，例如帧的解析函数、帧的生成函数等，来跟踪代码的执行流程，查看变量的值，从而找出问题的根源。

总而言之，`net/third_party/quiche/src/quiche/http2/core/spdy_protocol.cc` 文件是理解和调试 Chromium 中 HTTP/2 协议实现的关键入口点。它定义了协议的基础元素，并提供了操作这些元素的基本工具。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_protocol.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/core/spdy_protocol.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_flag_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace spdy {

const char* const kHttp2ConnectionHeaderPrefix =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

std::ostream& operator<<(std::ostream& out, SpdyKnownSettingsId id) {
  return out << static_cast<SpdySettingsId>(id);
}

std::ostream& operator<<(std::ostream& out, SpdyFrameType frame_type) {
  return out << SerializeFrameType(frame_type);
}

SpdyPriority ClampSpdy3Priority(SpdyPriority priority) {
  static_assert(std::numeric_limits<SpdyPriority>::min() == kV3HighestPriority,
                "The value of given priority shouldn't be smaller than highest "
                "priority. Check this invariant explicitly.");
  if (priority > kV3LowestPriority) {
    QUICHE_BUG(spdy_bug_22_1)
        << "Invalid priority: " << static_cast<int>(priority);
    return kV3LowestPriority;
  }
  return priority;
}

int ClampHttp2Weight(int weight) {
  if (weight < kHttp2MinStreamWeight) {
    QUICHE_BUG(spdy_bug_22_2) << "Invalid weight: " << weight;
    return kHttp2MinStreamWeight;
  }
  if (weight > kHttp2MaxStreamWeight) {
    QUICHE_BUG(spdy_bug_22_3) << "Invalid weight: " << weight;
    return kHttp2MaxStreamWeight;
  }
  return weight;
}

int Spdy3PriorityToHttp2Weight(SpdyPriority priority) {
  priority = ClampSpdy3Priority(priority);
  const float kSteps = 255.9f / 7.f;
  return static_cast<int>(kSteps * (7.f - priority)) + 1;
}

SpdyPriority Http2WeightToSpdy3Priority(int weight) {
  weight = ClampHttp2Weight(weight);
  const float kSteps = 255.9f / 7.f;
  return static_cast<SpdyPriority>(7.f - (weight - 1) / kSteps);
}

bool IsDefinedFrameType(uint8_t frame_type_field) {
  switch (static_cast<SpdyFrameType>(frame_type_field)) {
    case SpdyFrameType::DATA:
      return true;
    case SpdyFrameType::HEADERS:
      return true;
    case SpdyFrameType::PRIORITY:
      return true;
    case SpdyFrameType::RST_STREAM:
      return true;
    case SpdyFrameType::SETTINGS:
      return true;
    case SpdyFrameType::PUSH_PROMISE:
      return true;
    case SpdyFrameType::PING:
      return true;
    case SpdyFrameType::GOAWAY:
      return true;
    case SpdyFrameType::WINDOW_UPDATE:
      return true;
    case SpdyFrameType::CONTINUATION:
      return true;
    case SpdyFrameType::ALTSVC:
      return true;
    case SpdyFrameType::PRIORITY_UPDATE:
      return true;
    case SpdyFrameType::ACCEPT_CH:
      return true;
  }
  return false;
}

SpdyFrameType ParseFrameType(uint8_t frame_type_field) {
  QUICHE_BUG_IF(spdy_bug_22_4, !IsDefinedFrameType(frame_type_field))
      << "Frame type not defined: " << static_cast<int>(frame_type_field);
  return static_cast<SpdyFrameType>(frame_type_field);
}

uint8_t SerializeFrameType(SpdyFrameType frame_type) {
  return static_cast<uint8_t>(frame_type);
}

bool IsValidHTTP2FrameStreamId(SpdyStreamId current_frame_stream_id,
                               SpdyFrameType frame_type_field) {
  if (current_frame_stream_id == 0) {
    switch (frame_type_field) {
      case SpdyFrameType::DATA:
      case SpdyFrameType::HEADERS:
      case SpdyFrameType::PRIORITY:
      case SpdyFrameType::RST_STREAM:
      case SpdyFrameType::CONTINUATION:
      case SpdyFrameType::PUSH_PROMISE:
        // These frame types must specify a stream
        return false;
      default:
        return true;
    }
  } else {
    switch (frame_type_field) {
      case SpdyFrameType::GOAWAY:
      case SpdyFrameType::SETTINGS:
      case SpdyFrameType::PING:
        // These frame types must not specify a stream
        return false;
      default:
        return true;
    }
  }
}

const char* FrameTypeToString(SpdyFrameType frame_type) {
  switch (frame_type) {
    case SpdyFrameType::DATA:
      return "DATA";
    case SpdyFrameType::RST_STREAM:
      return "RST_STREAM";
    case SpdyFrameType::SETTINGS:
      return "SETTINGS";
    case SpdyFrameType::PING:
      return "PING";
    case SpdyFrameType::GOAWAY:
      return "GOAWAY";
    case SpdyFrameType::HEADERS:
      return "HEADERS";
    case SpdyFrameType::WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case SpdyFrameType::PUSH_PROMISE:
      return "PUSH_PROMISE";
    case SpdyFrameType::CONTINUATION:
      return "CONTINUATION";
    case SpdyFrameType::PRIORITY:
      return "PRIORITY";
    case SpdyFrameType::ALTSVC:
      return "ALTSVC";
    case SpdyFrameType::PRIORITY_UPDATE:
      return "PRIORITY_UPDATE";
    case SpdyFrameType::ACCEPT_CH:
      return "ACCEPT_CH";
  }
  return "UNKNOWN_FRAME_TYPE";
}

bool ParseSettingsId(SpdySettingsId wire_setting_id,
                     SpdyKnownSettingsId* setting_id) {
  if (wire_setting_id != SETTINGS_EXPERIMENT_SCHEDULER &&
      (wire_setting_id < SETTINGS_MIN || wire_setting_id > SETTINGS_MAX)) {
    return false;
  }

  *setting_id = static_cast<SpdyKnownSettingsId>(wire_setting_id);
  // This switch ensures that the casted value is valid. The default case is
  // explicitly omitted to have compile-time guarantees that new additions to
  // |SpdyKnownSettingsId| must also be handled here.
  switch (*setting_id) {
    case SETTINGS_HEADER_TABLE_SIZE:
    case SETTINGS_ENABLE_PUSH:
    case SETTINGS_MAX_CONCURRENT_STREAMS:
    case SETTINGS_INITIAL_WINDOW_SIZE:
    case SETTINGS_MAX_FRAME_SIZE:
    case SETTINGS_MAX_HEADER_LIST_SIZE:
    case SETTINGS_ENABLE_CONNECT_PROTOCOL:
    case SETTINGS_DEPRECATE_HTTP2_PRIORITIES:
    case SETTINGS_EXPERIMENT_SCHEDULER:
      return true;
  }
  return false;
}

std::string SettingsIdToString(SpdySettingsId id) {
  SpdyKnownSettingsId known_id;
  if (!ParseSettingsId(id, &known_id)) {
    return absl::StrCat("SETTINGS_UNKNOWN_", absl::Hex(uint32_t{id}));
  }

  switch (known_id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      return "SETTINGS_HEADER_TABLE_SIZE";
    case SETTINGS_ENABLE_PUSH:
      return "SETTINGS_ENABLE_PUSH";
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      return "SETTINGS_MAX_CONCURRENT_STREAMS";
    case SETTINGS_INITIAL_WINDOW_SIZE:
      return "SETTINGS_INITIAL_WINDOW_SIZE";
    case SETTINGS_MAX_FRAME_SIZE:
      return "SETTINGS_MAX_FRAME_SIZE";
    case SETTINGS_MAX_HEADER_LIST_SIZE:
      return "SETTINGS_MAX_HEADER_LIST_SIZE";
    case SETTINGS_ENABLE_CONNECT_PROTOCOL:
      return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
    case SETTINGS_DEPRECATE_HTTP2_PRIORITIES:
      return "SETTINGS_DEPRECATE_HTTP2_PRIORITIES";
    case SETTINGS_EXPERIMENT_SCHEDULER:
      return "SETTINGS_EXPERIMENT_SCHEDULER";
  }

  return absl::StrCat("SETTINGS_UNKNOWN_", absl::Hex(uint32_t{id}));
}

SpdyErrorCode ParseErrorCode(uint32_t wire_error_code) {
  if (wire_error_code > ERROR_CODE_MAX) {
    return ERROR_CODE_INTERNAL_ERROR;
  }

  return static_cast<SpdyErrorCode>(wire_error_code);
}

const char* ErrorCodeToString(SpdyErrorCode error_code) {
  switch (error_code) {
    case ERROR_CODE_NO_ERROR:
      return "NO_ERROR";
    case ERROR_CODE_PROTOCOL_ERROR:
      return "PROTOCOL_ERROR";
    case ERROR_CODE_INTERNAL_ERROR:
      return "INTERNAL_ERROR";
    case ERROR_CODE_FLOW_CONTROL_ERROR:
      return "FLOW_CONTROL_ERROR";
    case ERROR_CODE_SETTINGS_TIMEOUT:
      return "SETTINGS_TIMEOUT";
    case ERROR_CODE_STREAM_CLOSED:
      return "STREAM_CLOSED";
    case ERROR_CODE_FRAME_SIZE_ERROR:
      return "FRAME_SIZE_ERROR";
    case ERROR_CODE_REFUSED_STREAM:
      return "REFUSED_STREAM";
    case ERROR_CODE_CANCEL:
      return "CANCEL";
    case ERROR_CODE_COMPRESSION_ERROR:
      return "COMPRESSION_ERROR";
    case ERROR_CODE_CONNECT_ERROR:
      return "CONNECT_ERROR";
    case ERROR_CODE_ENHANCE_YOUR_CALM:
      return "ENHANCE_YOUR_CALM";
    case ERROR_CODE_INADEQUATE_SECURITY:
      return "INADEQUATE_SECURITY";
    case ERROR_CODE_HTTP_1_1_REQUIRED:
      return "HTTP_1_1_REQUIRED";
  }
  return "UNKNOWN_ERROR_CODE";
}

const char* WriteSchedulerTypeToString(WriteSchedulerType type) {
  switch (type) {
    case WriteSchedulerType::LIFO:
      return "LIFO";
    case WriteSchedulerType::SPDY:
      return "SPDY";
    case WriteSchedulerType::HTTP2:
      return "HTTP2";
    case WriteSchedulerType::FIFO:
      return "FIFO";
  }
  return "UNKNOWN";
}

size_t GetNumberRequiredContinuationFrames(size_t size) {
  QUICHE_DCHECK_GT(size, kHttp2MaxControlFrameSendSize);
  size_t overflow = size - kHttp2MaxControlFrameSendSize;
  int payload_size =
      kHttp2MaxControlFrameSendSize - kContinuationFrameMinimumSize;
  // This is ceiling(overflow/payload_size) using integer arithmetics.
  return (overflow - 1) / payload_size + 1;
}

const char* const kHttp2Npn = "h2";

const char* const kHttp2AuthorityHeader = ":authority";
const char* const kHttp2MethodHeader = ":method";
const char* const kHttp2PathHeader = ":path";
const char* const kHttp2SchemeHeader = ":scheme";
const char* const kHttp2ProtocolHeader = ":protocol";

const char* const kHttp2StatusHeader = ":status";

bool SpdyFrameIR::fin() const { return false; }

int SpdyFrameIR::flow_control_window_consumed() const { return 0; }

bool SpdyFrameWithFinIR::fin() const { return fin_; }

SpdyFrameWithHeaderBlockIR::SpdyFrameWithHeaderBlockIR(
    SpdyStreamId stream_id, quiche::HttpHeaderBlock header_block)
    : SpdyFrameWithFinIR(stream_id), header_block_(std::move(header_block)) {}

SpdyFrameWithHeaderBlockIR::~SpdyFrameWithHeaderBlockIR() = default;

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, std::string data)
    : SpdyFrameWithFinIR(stream_id),
      data_store_(std::move(data)),
      data_(data_store_->data()),
      data_len_(data_store_->size()),
      padded_(false),
      padding_payload_len_(0) {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id)
    : SpdyFrameWithFinIR(stream_id),
      data_(nullptr),
      data_len_(0),
      padded_(false),
      padding_payload_len_(0) {}

SpdyDataIR::~SpdyDataIR() = default;

void SpdyDataIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitData(*this);
}

SpdyFrameType SpdyDataIR::frame_type() const { return SpdyFrameType::DATA; }

int SpdyDataIR::flow_control_window_consumed() const {
  return padded_ ? 1 + padding_payload_len_ + data_len_ : data_len_;
}

size_t SpdyDataIR::size() const {
  return kFrameHeaderSize +
         (padded() ? 1 + padding_payload_len() + data_len() : data_len());
}

SpdyRstStreamIR::SpdyRstStreamIR(SpdyStreamId stream_id,
                                 SpdyErrorCode error_code)
    : SpdyFrameIR(stream_id) {
  set_error_code(error_code);
}

SpdyRstStreamIR::~SpdyRstStreamIR() = default;

void SpdyRstStreamIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitRstStream(*this);
}

SpdyFrameType SpdyRstStreamIR::frame_type() const {
  return SpdyFrameType::RST_STREAM;
}

size_t SpdyRstStreamIR::size() const { return kRstStreamFrameSize; }

SpdySettingsIR::SpdySettingsIR() : is_ack_(false) {}

SpdySettingsIR::~SpdySettingsIR() = default;

void SpdySettingsIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSettings(*this);
}

SpdyFrameType SpdySettingsIR::frame_type() const {
  return SpdyFrameType::SETTINGS;
}

size_t SpdySettingsIR::size() const {
  return kFrameHeaderSize + values_.size() * kSettingsOneSettingSize;
}

void SpdyPingIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPing(*this);
}

SpdyFrameType SpdyPingIR::frame_type() const { return SpdyFrameType::PING; }

size_t SpdyPingIR::size() const { return kPingFrameSize; }

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code,
                           absl::string_view description)
    : description_(description) {
  set_last_good_stream_id(last_good_stream_id);
  set_error_code(error_code);
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code, const char* description)
    : SpdyGoAwayIR(last_good_stream_id, error_code,
                   absl::string_view(description)) {}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code, std::string description)
    : description_store_(std::move(description)),
      description_(description_store_) {
  set_last_good_stream_id(last_good_stream_id);
  set_error_code(error_code);
}

SpdyGoAwayIR::~SpdyGoAwayIR() = default;

void SpdyGoAwayIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitGoAway(*this);
}

SpdyFrameType SpdyGoAwayIR::frame_type() const { return SpdyFrameType::GOAWAY; }

size_t SpdyGoAwayIR::size() const {
  return kGoawayFrameMinimumSize + description_.size();
}

SpdyContinuationIR::SpdyContinuationIR(SpdyStreamId stream_id)
    : SpdyFrameIR(stream_id), end_headers_(false) {}

SpdyContinuationIR::~SpdyContinuationIR() = default;

void SpdyContinuationIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitContinuation(*this);
}

SpdyFrameType SpdyContinuationIR::frame_type() const {
  return SpdyFrameType::CONTINUATION;
}

size_t SpdyContinuationIR::size() const {
  // We don't need to get the size of CONTINUATION frame directly. It is
  // calculated in HEADERS or PUSH_PROMISE frame.
  QUICHE_DLOG(WARNING) << "Shouldn't not call size() for CONTINUATION frame.";
  return 0;
}

void SpdyHeadersIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitHeaders(*this);
}

SpdyFrameType SpdyHeadersIR::frame_type() const {
  return SpdyFrameType::HEADERS;
}

size_t SpdyHeadersIR::size() const {
  size_t size = kHeadersFrameMinimumSize;

  if (padded_) {
    // Padding field length.
    size += 1;
    size += padding_payload_len_;
  }

  if (has_priority_) {
    size += 5;
  }

  // Assume no hpack encoding is applied.
  size += header_block().TotalBytesUsed() +
          header_block().size() * kPerHeaderHpackOverhead;
  if (size > kHttp2MaxControlFrameSendSize) {
    size += GetNumberRequiredContinuationFrames(size) *
            kContinuationFrameMinimumSize;
  }
  return size;
}

void SpdyWindowUpdateIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitWindowUpdate(*this);
}

SpdyFrameType SpdyWindowUpdateIR::frame_type() const {
  return SpdyFrameType::WINDOW_UPDATE;
}

size_t SpdyWindowUpdateIR::size() const { return kWindowUpdateFrameSize; }

void SpdyPushPromiseIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPushPromise(*this);
}

SpdyFrameType SpdyPushPromiseIR::frame_type() const {
  return SpdyFrameType::PUSH_PROMISE;
}

size_t SpdyPushPromiseIR::size() const {
  size_t size = kPushPromiseFrameMinimumSize;

  if (padded_) {
    // Padding length field.
    size += 1;
    size += padding_payload_len_;
  }

  size += header_block().TotalBytesUsed();
  if (size > kHttp2MaxControlFrameSendSize) {
    size += GetNumberRequiredContinuationFrames(size) *
            kContinuationFrameMinimumSize;
  }
  return size;
}

SpdyAltSvcIR::SpdyAltSvcIR(SpdyStreamId stream_id) : SpdyFrameIR(stream_id) {}

SpdyAltSvcIR::~SpdyAltSvcIR() = default;

void SpdyAltSvcIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitAltSvc(*this);
}

SpdyFrameType SpdyAltSvcIR::frame_type() const { return SpdyFrameType::ALTSVC; }

size_t SpdyAltSvcIR::size() const {
  size_t size = kGetAltSvcFrameMinimumSize;
  size += origin_.length();
  // TODO(yasong): estimates the size without serializing the vector.
  std::string str =
      SpdyAltSvcWireFormat::SerializeHeaderFieldValue(altsvc_vector_);
  size += str.size();
  return size;
}

void SpdyPriorityIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPriority(*this);
}

SpdyFrameType SpdyPriorityIR::frame_type() const {
  return SpdyFrameType::PRIORITY;
}

size_t SpdyPriorityIR::size() const { return kPriorityFrameSize; }

void SpdyPriorityUpdateIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPriorityUpdate(*this);
}

SpdyFrameType SpdyPriorityUpdateIR::frame_type() const {
  return SpdyFrameType::PRIORITY_UPDATE;
}

size_t SpdyPriorityUpdateIR::size() const {
  return kPriorityUpdateFrameMinimumSize + priority_field_value_.size();
}

void SpdyAcceptChIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitAcceptCh(*this);
}

SpdyFrameType SpdyAcceptChIR::frame_type() const {
  return SpdyFrameType::ACCEPT_CH;
}

size_t SpdyAcceptChIR::size() const {
  size_t total_size = kAcceptChFrameMinimumSize;
  for (const AcceptChOriginValuePair& entry : entries_) {
    total_size += entry.origin.size() + entry.value.size() +
                  kAcceptChFramePerEntryOverhead;
  }
  return total_size;
}

void SpdyUnknownIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitUnknown(*this);
}

SpdyFrameType SpdyUnknownIR::frame_type() const {
  return static_cast<SpdyFrameType>(type());
}

size_t SpdyUnknownIR::size() const {
  return kFrameHeaderSize + payload_.size();
}

int SpdyUnknownIR::flow_control_window_consumed() const {
  if (frame_type() == SpdyFrameType::DATA) {
    return payload_.size();
  } else {
    return 0;
  }
}

// Wire size of pad length field.
const size_t kPadLengthFieldSize = 1;

size_t GetHeaderFrameSizeSansBlock(const SpdyHeadersIR& header_ir) {
  size_t min_size = kFrameHeaderSize;
  if (header_ir.padded()) {
    min_size += kPadLengthFieldSize;
    min_size += header_ir.padding_payload_len();
  }
  if (header_ir.has_priority()) {
    min_size += 5;
  }
  return min_size;
}

size_t GetPushPromiseFrameSizeSansBlock(
    const SpdyPushPromiseIR& push_promise_ir) {
  size_t min_size = kPushPromiseFrameMinimumSize;
  if (push_promise_ir.padded()) {
    min_size += kPadLengthFieldSize;
    min_size += push_promise_ir.padding_payload_len();
  }
  return min_size;
}

}  // namespace spdy

"""

```