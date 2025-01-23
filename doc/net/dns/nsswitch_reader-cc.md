Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Understanding the Goal:**

The request asks for a comprehensive breakdown of the `nsswitch_reader.cc` file, focusing on its functionality, relationship to JavaScript (if any), logic inference examples, common usage errors, and debugging clues.

**2. Initial Code Scan and Keyword Identification:**

First, I'd quickly scan the code for keywords and structures to get a high-level understanding. I'd look for:

* **Includes:** `iostream` analogs (`string`, `vector`), file handling (`base/files`), functional programming (`base/functional`), metrics (`base/metrics`), string manipulation (`base/strings`), OS checks (`build/build_config`), and system calls (`netdb.h`). The `#include "net/dns/nsswitch_reader.h"` is crucial, indicating this is the implementation file for the `NsswitchReader` class.
* **Namespaces:** The code resides within the `net` namespace, suggesting its role in network operations.
* **Constants:** `kNsswitchPath` and `kMaxFileSize` immediately stand out as important configuration values.
* **Functions:**  Functions like `ReadNsswitch`, `FindDatabase`, `TokenizeAction`, `TokenizeActions`, `TokenizeService`, `TokenizeDatabase`, and `ReadAndParseHosts` are the core logic.
* **Classes/Structs:** The `NsswitchReader` class and the nested `ServiceSpecification` struct are central to the file's purpose. The `ServiceAction` struct within `ServiceSpecification` is also important.
* **Conditional Compilation:** `#if BUILDFLAG(IS_POSIX)` indicates platform-specific behavior.
* **Macros:** `UMA_HISTOGRAM_BOOLEAN` suggests logging and metrics collection.
* **Core Logic Area:** The `Tokenize...` functions strongly suggest parsing and data processing.

**3. Deconstructing the Functionality (Step-by-Step):**

With the initial scan done, I'd analyze the functions more deeply, starting with the entry point for reading:

* **`ReadNsswitch()`:**  Clearly reads the `/etc/nsswitch.conf` file (or a platform-specific alternative). The `UMA_HISTOGRAM_BOOLEAN` calls indicate it tracks success and cases where the file is too large. This function's purpose is simply to get the raw file content.

* **`FindDatabase()`:** This function searches the content for a specific database entry (like "hosts:"). The `DCHECK` statements are important for understanding the expected input format. It extracts the line associated with the database.

* **`TokenizeDatabase()`:**  This is the core parsing logic. It breaks down the line extracted by `FindDatabase` into a vector of `ServiceSpecification` objects. It handles comments, service names, and action lists within brackets. The logic for handling brackets and whitespace is critical here.

* **`TokenizeService()`:** Converts individual service names (like "files", "dns") into `Service` enum values.

* **`TokenizeActions()`:** Splits the action string (within brackets) into individual actions.

* **`TokenizeAction()`:** Parses a single action (e.g., "!SUCCESS=RETURN") into its `negated`, `status`, and `action` components.

* **`ReadAndParseHosts()`:** This function orchestrates the process: read the file, find the "hosts" database, and tokenize it. It also provides a default if the file or the "hosts" entry is missing.

**4. Identifying the Core Purpose:**

Based on the function names and their interactions, the core purpose is evident: to read and parse the `/etc/nsswitch.conf` file, specifically focusing on the "hosts" database. This file dictates the order in which different services (like local files, DNS) are queried for hostname resolution.

**5. Assessing the Relationship with JavaScript:**

Given that this is a low-level C++ networking component, a direct relationship with JavaScript is unlikely. However, Chromium uses this code internally. When JavaScript running in a browser needs to resolve a hostname (e.g., when you type a URL), the browser's network stack, which includes this C++ code, will be involved in the resolution process. The key is the *indirect* relationship.

**6. Constructing Logic Inference Examples:**

To demonstrate the parsing logic, I'd create simple examples of `nsswitch.conf` entries and trace how `TokenizeDatabase` would process them. This involves considering different combinations of services, actions, and formatting.

**7. Identifying Common Usage Errors:**

Think about what could go wrong from a user or programmer perspective. Users typically don't directly interact with this file in a browser context, but system administrators do. Incorrect syntax in `/etc/nsswitch.conf` is the primary user error. For programmers, the error is more about incorrectly using or understanding the output of the `NsswitchReader`.

**8. Tracing User Operations and Debugging:**

Consider the chain of events that leads to this code being executed. A user typing a URL is the most common trigger. Then, the browser's network stack initiates the hostname resolution process, eventually consulting the `/etc/nsswitch.conf` file. Debugging involves looking at the file's contents, the output of the parsing functions, and any error conditions reported by the code (like the histograms).

**9. Structuring the Explanation:**

Finally, organize the findings into a clear and logical structure, addressing each part of the original request. Use headings, bullet points, and code examples to make the explanation easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly interacts with some JavaScript API.
* **Correction:** After more careful analysis, it's clear the interaction is *indirect*. JavaScript triggers a high-level network request, which filters down to this C++ component.
* **Initial thought:** Focus heavily on all possible parsing scenarios.
* **Refinement:**  Focus on the *most common* and illustrative scenarios for the logic inference examples. Avoid getting bogged down in overly complex edge cases initially.
* **Initial thought:**  Overlook the importance of the `UMA_HISTOGRAM_BOOLEAN` calls.
* **Correction:** Recognize that these calls are valuable for understanding how the code is monitored and for identifying potential issues.

By following this structured approach, combining code analysis with reasoning and consideration of the broader context, I could generate the comprehensive explanation provided earlier.
这个文件 `net/dns/nsswitch_reader.cc` 是 Chromium 网络栈的一部分，它的主要功能是 **读取和解析操作系统级别的名称服务切换 (Name Service Switch, NSS) 配置文件 `/etc/nsswitch.conf` (或其平台特定的位置)。**

这个文件的目的是确定在进行主机名查找（DNS 解析）时，应该按照什么样的顺序和规则来查询不同的名称服务源，例如本地文件 (`/etc/hosts`)、DNS 服务器等。

**具体功能分解：**

1. **读取 `/etc/nsswitch.conf` 文件内容:**
   - 使用 `base::ReadFileToStringWithMaxSize` 函数读取指定路径下的 `nsswitch.conf` 文件。
   - 设置了最大文件大小 `kMaxFileSize`，防止读取过大的文件。
   - 使用宏 `UMA_HISTOGRAM_BOOLEAN` 记录文件读取是否成功以及文件是否过大。

2. **查找指定的数据库配置:**
   - `FindDatabase` 函数接收文件内容和要查找的数据库名称（例如 "hosts:"）。
   - 它会遍历文件内容，查找以指定名称开头的行，忽略大小写。
   - 返回找到的配置行的内容，去除前后的空格。

3. **解析数据库配置:**
   - `TokenizeDatabase` 函数接收数据库配置字符串（例如 "files dns [NOTFOUND=return]"）。
   - 它会将配置字符串分解成不同的服务规范 (`ServiceSpecification`)。
   - 它会识别服务名称（例如 "files", "dns"）和操作列表（用方括号 `[]` 包围）。

4. **解析服务规范:**
   - `TokenizeService` 函数将服务名称字符串转换为 `NsswitchReader::Service` 枚举值，例如 "files" 对应 `NsswitchReader::Service::kFiles`。

5. **解析操作列表:**
   - `TokenizeActions` 函数将操作列表字符串（例如 "NOTFOUND=return continue"）分解成多个操作 (`ServiceAction`)。

6. **解析单个操作:**
   - `TokenizeAction` 函数将单个操作字符串（例如 "SUCCESS=return", "!UNAVAIL=continue"）解析成包含状态、动作和是否取反 (`negated`) 的结构体 `ServiceAction`。

7. **提供默认配置:**
   - `GetDefaultHosts` 函数在读取配置文件失败或未找到 "hosts" 配置时，提供一个默认的 "hosts" 配置，通常是先查询本地文件，再查询 DNS。

8. **`NsswitchReader` 类:**
   - 封装了读取和解析 `nsswitch.conf` 文件的逻辑。
   - `ReadAndParseHosts` 函数是主要的接口，用于读取并解析 "hosts" 数据库的配置。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它 **间接地** 与 JavaScript 的功能相关。

- 当在 Chromium 浏览器中，JavaScript 代码需要解析主机名（例如，通过 `fetch` API 或访问一个 URL 时），浏览器底层的网络栈会执行主机名查找操作。
- 这个 `nsswitch_reader.cc` 文件读取的配置信息会影响主机名查找的顺序和行为。例如，如果 `/etc/nsswitch.conf` 中 "hosts" 配置先列出 "dns"，那么系统会先尝试使用 DNS 服务器解析主机名。

**举例说明:**

假设 `/etc/nsswitch.conf` 文件包含以下内容：

```
passwd:         compat
group:          compat
shadow:         compat
hosts:          files dns mdns4_minimal [NOTFOUND=return]
networks:       files
protocols:      db files
services:       db files
ethers:         db files
rpc:            db files
```

当 Chromium 的网络栈需要解析主机名时，`NsswitchReader::ReadAndParseHosts()` 函数会被调用，它会执行以下步骤：

1. 读取 `/etc/nsswitch.conf` 的内容。
2. 使用 `FindDatabase` 找到 "hosts:" 对应的行："files dns mdns4_minimal [NOTFOUND=return]"。
3. 使用 `TokenizeDatabase` 解析该行：
   - 服务 1: `files`，没有关联的操作。
   - 服务 2: `dns`，没有关联的操作。
   - 服务 3: `mdns4_minimal`，关联的操作是 `[NOTFOUND=return]`。
4. 使用 `TokenizeActions` 解析 `[NOTFOUND=return]`：
   - 操作 1: `NOTFOUND=return`，转换为 `ServiceAction`，`status` 为 `kNotFound`，`action` 为 `kReturn`。

**逻辑推理，假设输入与输出:**

**假设输入 (部分 `/etc/nsswitch.conf`)：**

```
hosts:          files dns [SUCCESS=return] mdns
```

**输出 (经过 `TokenizeDatabase` 处理后的 `std::vector<NsswitchReader::ServiceSpecification>`):**

```
[
  { service: kFiles, actions: [] },
  { service: kDns, actions: [{ negated: false, status: kSuccess, action: kReturn }] },
  { service: kMdns, actions: [] }
]
```

**解释:**

- 首先解析出 `files` 服务，没有关联的操作。
- 接着解析出 `dns` 服务，关联的操作列表是 `[SUCCESS=return]`。
- `TokenizeActions` 将 `[SUCCESS=return]` 解析为一个 `ServiceAction`，表示如果 DNS 查询成功 (`SUCCESS`)，则立即返回结果 (`return`)，不再继续查询后续的服务。
- 最后解析出 `mdns` 服务，没有关联的操作。

**用户或编程常见的使用错误:**

1. **错误的配置文件语法:**
   - **错误示例:** `hosts: files, dns` (应该使用空格分隔服务)
   - **结果:** 解析器可能无法正确识别服务，导致主机名解析行为异常。

2. **操作符错误:**
   - **错误示例:** `hosts: dns [NOTFOUND=retun]` (拼写错误，应该是 `return`)
   - **结果:** 解析器可能无法识别该操作，将其视为未知操作。

3. **逻辑错误:**
   - **错误示例:** `hosts: files [NOTFOUND=continue] files` (重复列出 `files`，可能导致意外行为)
   - **结果:** 可能会导致不必要的查询，影响性能。

4. **权限问题:**
   - 用户运行 Chromium 的进程没有读取 `/etc/nsswitch.conf` 文件的权限。
   - **结果:** `ReadNsswitch` 函数会返回空字符串，导致使用默认配置。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 Chromium 浏览器中输入一个 URL (例如 `www.example.com`) 并按下回车。**
2. **Chromium 的渲染进程接收到用户请求。**
3. **渲染进程需要知道 `www.example.com` 的 IP 地址，因此会向网络进程发起主机名解析请求。**
4. **网络进程接收到主机名解析请求。**
5. **网络进程需要确定如何进行主机名解析，这涉及到读取操作系统级别的配置。**
6. **`net::NsswitchReader::ReadAndParseHosts()` 函数被调用。**
7. **`ReadNsswitch()` 函数尝试读取 `/etc/nsswitch.conf` 文件。**
8. **`FindDatabase()` 函数在文件内容中查找 "hosts:" 开头的行。**
9. **`TokenizeDatabase()` 函数解析找到的 "hosts" 配置字符串。**
10. **解析后的配置信息被网络进程用于指导主机名解析过程，决定先查询本地文件还是 DNS 服务器。**

**调试线索:**

- **检查 `/etc/nsswitch.conf` 文件的内容和语法:** 确认配置是否符合预期，是否存在拼写错误或语法错误。
- **检查文件读取权限:** 确认运行 Chromium 的用户是否有权限读取 `/etc/nsswitch.conf` 文件。
- **使用 Chromium 的内部日志 (`chrome://net-internals/#dns`)**: 可以查看 Chromium 的 DNS 解析过程，包括使用了哪些配置信息。
- **使用系统工具 (例如 `getent hosts <hostname>`)**: 可以查看操作系统层面是如何解析主机名的，与 Chromium 的行为进行对比。
- **在 `nsswitch_reader.cc` 中添加日志输出 (例如 `DLOG` 或 `VLOG`):** 可以打印读取的文件内容、解析的中间结果，帮助理解代码的执行流程。
- **使用调试器 (例如 gdb):** 可以断点到 `ReadAndParseHosts` 函数，单步执行，查看变量的值，分析解析过程。

总而言之，`net/dns/nsswitch_reader.cc` 文件在 Chromium 的网络栈中扮演着重要的角色，它负责读取和解析操作系统级别的名称服务切换配置，从而影响着浏览器进行主机名解析的行为。理解其功能和可能的错误，对于排查网络连接问题至关重要。

### 提示词
```
这是目录为net/dns/nsswitch_reader.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/nsswitch_reader.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <netdb.h>
#endif  // defined (OS_POSIX)

namespace net {

namespace {

#ifdef _PATH_NSSWITCH_CONF
constexpr base::FilePath::CharType kNsswitchPath[] =
    FILE_PATH_LITERAL(_PATH_NSSWITCH_CONF);
#else
constexpr base::FilePath::CharType kNsswitchPath[] =
    FILE_PATH_LITERAL("/etc/nsswitch.conf");
#endif

// Choose 1 MiB as the largest handled filesize. Arbitrarily chosen as seeming
// large enough to handle any reasonable file contents and similar to the size
// limit for HOSTS files (32 MiB).
constexpr size_t kMaxFileSize = 1024 * 1024;

std::string ReadNsswitch() {
  std::string file;
  bool result = base::ReadFileToStringWithMaxSize(base::FilePath(kNsswitchPath),
                                                  &file, kMaxFileSize);
  UMA_HISTOGRAM_BOOLEAN("Net.DNS.DnsConfig.Nsswitch.Read",
                        result || file.size() == kMaxFileSize);
  UMA_HISTOGRAM_BOOLEAN("Net.DNS.DnsConfig.Nsswitch.TooLarge",
                        !result && file.size() == kMaxFileSize);

  if (result)
    return file;

  return "";
}

std::string_view SkipRestOfLine(std::string_view text) {
  std::string_view::size_type line_end = text.find('\n');
  if (line_end == std::string_view::npos) {
    return "";
  }
  return text.substr(line_end);
}

// In case of multiple entries for `database_name`, finds only the first.
std::string_view FindDatabase(std::string_view text,
                              std::string_view database_name) {
  DCHECK(!text.empty());
  DCHECK(!database_name.empty());
  DCHECK(!database_name.starts_with("#"));
  DCHECK(!base::IsAsciiWhitespace(database_name.front()));
  DCHECK(database_name.ends_with(":"));

  while (!text.empty()) {
    text = base::TrimWhitespaceASCII(text, base::TrimPositions::TRIM_LEADING);

    if (base::StartsWith(text, database_name,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      DCHECK(!text.starts_with("#"));

      text = text.substr(database_name.size());
      std::string_view::size_type line_end = text.find('\n');
      if (line_end != std::string_view::npos) {
        text = text.substr(0, line_end);
      }

      return base::TrimWhitespaceASCII(text, base::TrimPositions::TRIM_ALL);
    }

    text = SkipRestOfLine(text);
  }

  return "";
}

NsswitchReader::ServiceAction TokenizeAction(std::string_view action_column) {
  DCHECK(!action_column.empty());
  DCHECK_EQ(action_column.find(']'), std::string_view::npos);
  DCHECK_EQ(action_column.find_first_of(base::kWhitespaceASCII),
            std::string_view::npos);

  NsswitchReader::ServiceAction result = {/*negated=*/false,
                                          NsswitchReader::Status::kUnknown,
                                          NsswitchReader::Action::kUnknown};

  std::vector<std::string_view> split = base::SplitStringPiece(
      action_column, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (split.size() != 2)
    return result;

  if (split[0].size() >= 2 && split[0].front() == '!') {
    result.negated = true;
    split[0] = split[0].substr(1);
  }

  if (base::EqualsCaseInsensitiveASCII(split[0], "SUCCESS")) {
    result.status = NsswitchReader::Status::kSuccess;
  } else if (base::EqualsCaseInsensitiveASCII(split[0], "NOTFOUND")) {
    result.status = NsswitchReader::Status::kNotFound;
  } else if (base::EqualsCaseInsensitiveASCII(split[0], "UNAVAIL")) {
    result.status = NsswitchReader::Status::kUnavailable;
  } else if (base::EqualsCaseInsensitiveASCII(split[0], "TRYAGAIN")) {
    result.status = NsswitchReader::Status::kTryAgain;
  }

  if (base::EqualsCaseInsensitiveASCII(split[1], "RETURN")) {
    result.action = NsswitchReader::Action::kReturn;
  } else if (base::EqualsCaseInsensitiveASCII(split[1], "CONTINUE")) {
    result.action = NsswitchReader::Action::kContinue;
  } else if (base::EqualsCaseInsensitiveASCII(split[1], "MERGE")) {
    result.action = NsswitchReader::Action::kMerge;
  }

  return result;
}

std::vector<NsswitchReader::ServiceAction> TokenizeActions(
    std::string_view actions) {
  DCHECK(!actions.empty());
  DCHECK_NE(actions.front(), '[');
  DCHECK_EQ(actions.find(']'), std::string_view::npos);
  DCHECK(!base::IsAsciiWhitespace(actions.front()));

  std::vector<NsswitchReader::ServiceAction> result;

  for (const auto& action_column : base::SplitStringPiece(
           actions, base::kWhitespaceASCII, base::KEEP_WHITESPACE,
           base::SPLIT_WANT_NONEMPTY)) {
    DCHECK(!action_column.empty());
    result.push_back(TokenizeAction(action_column));
  }

  return result;
}

NsswitchReader::ServiceSpecification TokenizeService(
    std::string_view service_column) {
  DCHECK(!service_column.empty());
  DCHECK_EQ(service_column.find_first_of(base::kWhitespaceASCII),
            std::string_view::npos);
  DCHECK_NE(service_column.front(), '[');

  if (base::EqualsCaseInsensitiveASCII(service_column, "files")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kFiles);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "dns")) {
    return NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns")) {
    return NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns4")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMdns4);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns6")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMdns6);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns_minimal")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMdnsMinimal);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns4_minimal")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMdns4Minimal);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "mdns6_minimal")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMdns6Minimal);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "myhostname")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kMyHostname);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "resolve")) {
    return NsswitchReader::ServiceSpecification(
        NsswitchReader::Service::kResolve);
  }
  if (base::EqualsCaseInsensitiveASCII(service_column, "nis")) {
    return NsswitchReader::ServiceSpecification(NsswitchReader::Service::kNis);
  }

  return NsswitchReader::ServiceSpecification(
      NsswitchReader::Service::kUnknown);
}

// Returns the actions string without brackets. `out_num_bytes` returns number
// of bytes in the actions including brackets and trailing whitespace.
std::string_view GetActionsStringAndRemoveBrackets(std::string_view database,
                                                   size_t& out_num_bytes) {
  DCHECK(!database.empty());
  DCHECK_EQ(database.front(), '[');

  size_t action_end = database.find(']');

  std::string_view actions;
  if (action_end == std::string_view::npos) {
    actions = database.substr(1);
    out_num_bytes = database.size();
  } else {
    actions = database.substr(1, action_end - 1);
    out_num_bytes = action_end;
  }

  // Ignore repeated '[' at start of `actions`.
  actions =
      base::TrimWhitespaceASCII(actions, base::TrimPositions::TRIM_LEADING);
  while (!actions.empty() && actions.front() == '[') {
    actions = base::TrimWhitespaceASCII(actions.substr(1),
                                        base::TrimPositions::TRIM_LEADING);
  }

  // Include any trailing ']' and whitespace in `out_num_bytes`.
  while (out_num_bytes < database.size() &&
         (database[out_num_bytes] == ']' ||
          base::IsAsciiWhitespace(database[out_num_bytes]))) {
    ++out_num_bytes;
  }

  return actions;
}

std::vector<NsswitchReader::ServiceSpecification> TokenizeDatabase(
    std::string_view database) {
  std::vector<NsswitchReader::ServiceSpecification> tokenized;

  while (!database.empty()) {
    DCHECK(!base::IsAsciiWhitespace(database.front()));

    // Note: Assuming comments are not recognized mid-action or mid-service.
    if (database.front() == '#') {
      // Once a comment is hit, the rest of the database is comment.
      return tokenized;
    }

    if (database.front() == '[') {
      // Actions are expected to come after a service.
      if (tokenized.empty()) {
        tokenized.emplace_back(NsswitchReader::Service::kUnknown);
      }

      size_t num_actions_bytes = 0;
      std::string_view actions =
          GetActionsStringAndRemoveBrackets(database, num_actions_bytes);

      if (num_actions_bytes == database.size()) {
        database = "";
      } else {
        database = database.substr(num_actions_bytes);
      }

      if (!actions.empty()) {
        std::vector<NsswitchReader::ServiceAction> tokenized_actions =
            TokenizeActions(actions);
        tokenized.back().actions.insert(tokenized.back().actions.end(),
                                        tokenized_actions.begin(),
                                        tokenized_actions.end());
      }
    } else {
      size_t column_end = database.find_first_of(base::kWhitespaceASCII);

      std::string_view service_column;
      if (column_end == std::string_view::npos) {
        service_column = database;
        database = "";
      } else {
        service_column = database.substr(0, column_end);
        database = database.substr(column_end);
      }

      tokenized.push_back(TokenizeService(service_column));
    }

    database =
        base::TrimWhitespaceASCII(database, base::TrimPositions::TRIM_LEADING);
  }

  return tokenized;
}

std::vector<NsswitchReader::ServiceSpecification> GetDefaultHosts() {
  return {NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)};
}

}  // namespace

NsswitchReader::ServiceSpecification::ServiceSpecification(
    Service service,
    std::vector<ServiceAction> actions)
    : service(service), actions(std::move(actions)) {}

NsswitchReader::ServiceSpecification::~ServiceSpecification() = default;

NsswitchReader::ServiceSpecification::ServiceSpecification(
    const ServiceSpecification&) = default;

NsswitchReader::ServiceSpecification&
NsswitchReader::ServiceSpecification::operator=(const ServiceSpecification&) =
    default;

NsswitchReader::ServiceSpecification::ServiceSpecification(
    ServiceSpecification&&) = default;

NsswitchReader::ServiceSpecification&
NsswitchReader::ServiceSpecification::operator=(ServiceSpecification&&) =
    default;

NsswitchReader::NsswitchReader()
    : file_read_call_(base::BindRepeating(&ReadNsswitch)) {}

NsswitchReader::~NsswitchReader() = default;

std::vector<NsswitchReader::ServiceSpecification>
NsswitchReader::ReadAndParseHosts() {
  std::string file = file_read_call_.Run();
  if (file.empty())
    return GetDefaultHosts();

  std::string_view hosts = FindDatabase(file, "hosts:");
  if (hosts.empty())
    return GetDefaultHosts();

  return TokenizeDatabase(hosts);
}

}  // namespace net
```