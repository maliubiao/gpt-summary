Response:
Let's break down the thought process for analyzing the `cachetool.cc` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of this Chromium network stack tool. The request also asks specifically about its relationship to JavaScript, logical reasoning (input/output examples), common usage errors, and debugging steps.

**2. Initial Skim and Keyword Recognition:**

First, I would quickly scan the code for obvious keywords and patterns. Things that jump out:

* **`cachetool`:** This is the name of the tool, so it's clearly related to cache management.
* **`disk_cache`:**  This confirms it's about disk caching.
* **`Backend`, `Entry`, `Iterator`:** These suggest interactions with a cache storage mechanism.
* **Command names (like `get_size`, `list_keys`, `delete_key`):**  This strongly indicates a command-line interface.
* **`ProgramArgumentCommandMarshal`, `StreamCommandMarshal`:**  These suggest different ways of receiving commands (command line vs. standard input).
* **`net::HttpResponseHeaders`, `net::HttpResponseInfo`:** This points to handling HTTP caching.
* **`base::MD5`:**  Indicates some form of content hashing, likely for identifying duplicates.
* **`PrintHelp()`:**  Confirms a command-line tool with usage instructions.

**3. Identifying Core Functionality:**

Based on the command names and the general code structure, I can deduce the main functions of the tool:

* **Cache Inspection:**  Getting size, listing keys, listing duplicate content.
* **Cache Modification:** Deleting keys, deleting specific streams within keys, updating/setting headers.
* **Basic Cache Operations:** Starting and stopping (implicitly by opening and closing the cache).
* **Batch Processing:** The `batch` command and `StreamCommandMarshal` suggest processing commands from standard input.

**4. Analyzing the Command Handling Mechanism:**

The `CommandMarshal` class and its derived classes are central. I'd focus on understanding how commands are read and how results are returned. The two main implementations (`ProgramArgumentCommandMarshal` and `StreamCommandMarshal`) are crucial for understanding the two modes of operation.

**5. Addressing the JavaScript Relationship:**

This is where careful consideration is needed. Directly, this C++ tool doesn't *execute* JavaScript. However, it interacts with the browser's cache, which *stores* resources used by JavaScript (like scripts, images, etc.). The connection is indirect but important. I need to explain that `cachetool` operates on the *underlying storage* used by the browser, including what JavaScript relies on. Examples of JavaScript-related cached resources are key here.

**6. Constructing Logical Reasoning Examples (Input/Output):**

For each command, I need to think of a realistic scenario and the corresponding input and output. The command-line syntax provided in `PrintHelp()` is essential for creating valid input examples. The output will vary depending on the command's success or failure and the state of the cache.

**7. Identifying Common Usage Errors:**

This involves thinking about what could go wrong when a user interacts with the tool:

* **Incorrect command-line arguments:** Wrong number of arguments, invalid command names, incorrect data types.
* **Invalid cache path or type:**  The tool needs a valid cache to operate on.
* **Operating on non-existent keys:**  Many commands require a specific key.
* **Incorrect stream indices:**  `get_stream` and `delete_stream` require valid indices.
* **Providing malformed input (especially for `update_raw_headers`):**  The tool expects valid HTTP headers.

**8. Tracing User Actions (Debugging Clues):**

This requires thinking about how a user might end up using `cachetool`. It's primarily a developer/debugging tool, not something an average user directly interacts with. The steps would involve:

* **Identifying a caching issue in the browser.**
* **Locating the browser's cache directory.**
* **Using `cachetool` with the correct path and command to investigate or modify the cache.**

**9. Structuring the Response:**

Finally, I would organize the findings into clear sections, addressing each part of the request:

* **Functionality:**  A high-level overview of what the tool does.
* **Relationship with JavaScript:** Emphasizing the indirect connection through cached resources.
* **Logical Reasoning (Input/Output):** Providing concrete examples for various commands.
* **Common Usage Errors:** Listing potential mistakes and their causes.
* **User Actions and Debugging:** Describing the typical workflow of using the tool for debugging.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This tool manipulates the HTTP cache."
* **Refinement:** "This tool manipulates the *disk cache*, which includes HTTP cache data but also potentially other cached resources."
* **Initial thought:** "JavaScript directly calls this tool."
* **Refinement:** "JavaScript uses the browser's caching mechanisms. This tool operates on the underlying storage of that cache."

By following this structured approach, combining code analysis with logical reasoning and considering the user's perspective, I can generate a comprehensive and accurate explanation of the `cachetool.cc` file.
这是 `net/tools/cachetool/cachetool.cc` 文件的功能分析：

**功能总览:**

`cachetool` 是一个命令行工具，用于检查和操作 Chromium 网络栈的磁盘缓存。它允许开发者和调试人员查看、修改和管理缓存的内容。  你可以使用它来：

* **查看缓存信息:** 获取缓存大小，列出所有缓存条目的键（URL），查找具有重复主体内容的条目。
* **读取缓存内容:** 获取特定缓存条目的指定数据流（例如，HTTP 响应头或主体内容）。
* **修改缓存条目:**  删除特定的缓存条目或条目的某个数据流，更新或设置缓存条目的 HTTP 响应头。
* **验证缓存状态:**  通过尝试打开缓存来验证其存在和类型。
* **批量操作:** 通过标准输入接收一系列命令并执行。

**与 JavaScript 功能的关系:**

`cachetool` 本身是用 C++ 编写的，并不直接包含 JavaScript 代码或执行 JavaScript。然而，它操作的磁盘缓存存储了浏览器用于加载网页的各种资源，其中可能包括 JavaScript 文件。 因此，`cachetool` 的操作会间接影响 JavaScript 的行为。

**举例说明:**

假设一个网站的 JavaScript 文件 `script.js` 被缓存了。

1. **查看缓存中 JavaScript 文件:**
   - 你可以使用 `cachetool` 的 `list_keys` 命令列出所有缓存的 URL，如果 `script.js` 被缓存了，它的 URL 应该会出现在列表中。
   - `cachetool <cache_path> blockfile list_keys`

2. **获取 JavaScript 文件的内容:**
   - 使用 `get_stream` 命令和 `script.js` 的 URL 以及内容流索引（通常是 1）可以查看缓存的 JavaScript 文件内容。
   - `cachetool <cache_path> blockfile get_stream https://example.com/script.js 1`
   - 如果缓存中有对应的条目，`cachetool` 会将 `script.js` 的内容输出到终端。

3. **删除缓存的 JavaScript 文件:**
   - 使用 `delete_key` 命令可以删除 `script.js` 的缓存条目。
   - `cachetool <cache_path> blockfile delete_key https://example.com/script.js`
   - 执行此命令后，当浏览器下次请求 `script.js` 时，它将不得不重新从服务器下载，而不是从缓存加载。

4. **修改 JavaScript 文件的响应头 (间接影响):**
   - 虽然不能直接修改缓存的 JavaScript 文件内容，但可以修改其缓存的响应头。 例如，可以修改 `Cache-Control` 头来强制浏览器重新验证或延长缓存时间。 这会影响浏览器如何处理和加载该 JavaScript 文件。
   - 首先获取当前的响应头： `cachetool <cache_path> blockfile get_stream https://example.com/script.js 0`
   - 然后使用 `set_header` 命令修改头信息： `cachetool <cache_path> blockfile set_header https://example.com/script.js Cache-Control "max-age=3600"`

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `cache_path`:  `/tmp/my_cache` (缓存路径)
* `cache_backend_type`: `blockfile` (缓存后端类型)
* `subcommand`: `get_size`

**预期输出:**

* 如果缓存存在且可以访问，`cachetool` 将输出缓存的总大小（字节数），例如：
  ```
  0
  123456789
  ```
  第一行的 `0` 表示命令成功，第二行是缓存的大小。
* 如果缓存不存在或无法访问，`cachetool` 将输出错误信息，例如：
  ```
  Invalid cache.
  ```

**假设输入:**

* `cache_path`:  `/tmp/my_cache`
* `cache_backend_type`: `simple`
* `subcommand`: `get_stream`
* `key`: `https://example.com/image.png`
* `index`: `1` (假设是内容流)

**预期输出:**

* 如果缓存中存在 `https://example.com/image.png` 的条目，并且索引 1 的数据流存在，`cachetool` 将输出该数据流的内容（可能是图像的二进制数据）。
* 如果缓存中不存在该键或索引，`cachetool` 将输出错误信息，例如：
  ```
  Couldn't find key's entry.
  ```
  或
  ```
  Stream read error.
  ```

**涉及用户或编程常见的使用错误 (举例说明):**

1. **错误的缓存路径:**
   - **错误:** 用户提供了不存在或错误的缓存路径。
   - **命令:** `cachetool /invalid/cache/path blockfile get_size`
   - **输出:** `Invalid cache.`
   - **原因:** `cachetool` 无法找到或打开指定的缓存目录。

2. **错误的缓存后端类型:**
   - **错误:** 用户指定了与实际缓存类型不符的后端类型。
   - **命令:** `cachetool /tmp/my_cache simple get_size` (假设实际缓存是 `blockfile` 类型)
   - **输出:**  可能输出 `Invalid cache.` 或其他与缓存打开失败相关的错误信息。
   - **原因:** `cachetool` 使用指定的后端类型尝试打开缓存，如果类型不匹配则会失败。

3. **操作不存在的键:**
   - **错误:** 用户尝试对缓存中不存在的键执行操作。
   - **命令:** `cachetool /tmp/my_cache blockfile get_stream https://nonexistent.com/page.html 1`
   - **输出:** `Couldn't find key's entry.`
   - **原因:** 缓存中没有与指定 URL 匹配的条目。

4. **错误的流索引:**
   - **错误:** 用户提供了超出有效范围的流索引。
   - **命令:** `cachetool /tmp/my_cache blockfile get_stream https://example.com/page.html 5`
   - **输出:** `Invalid stream index.` 或在流处理时报错。
   - **原因:** 每个缓存条目只有有限数量的数据流（通常是 0, 1, 2）。

5. **批量操作时格式错误:**
   - **错误:** 当使用 `batch` 命令并通过标准输入传递命令时，输入的命令格式不正确。
   - **假设输入 (stdin):**
     ```
     get_size extra_argument
     stop
     ```
   - **输出:** `Unknown command.` (因为 `get_size` 命令不应有额外的参数) 或其他解析错误信息。
   - **原因:** `StreamCommandMarshal` 期望特定格式的输入，额外的参数会导致解析失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者遇到了一个与缓存相关的问题，例如网页资源没有按预期更新。以下是他们可能使用 `cachetool` 进行调试的步骤：

1. **识别问题:** 开发者发现浏览器加载了旧版本的 JavaScript 或 CSS 文件，尽管服务器上已经更新了。

2. **查找缓存路径:** 开发者需要找到 Chromium 浏览器使用的磁盘缓存路径。这取决于操作系统和浏览器配置。常见的路径可能在用户配置目录下，例如 Linux 上的 `~/.config/chromium/Default/Cache` 或 macOS 上的 `~/Library/Application Support/Google/Chrome/Default/Cache`.

3. **确定缓存后端类型:**  Chromium 可能使用不同的缓存后端。通常，最新的版本倾向于使用 `blockfile`。  如果不知道，可以尝试不同的类型。

4. **使用 `list_keys` 列出缓存内容:** 开发者使用 `list_keys` 命令查看缓存中是否存在相关的资源 URL。
   ```bash
   cachetool ~/.config/chromium/Default/Cache blockfile list_keys
   ```
   他们会在输出中查找问题资源的 URL。

5. **使用 `get_stream` 查看缓存内容和响应头:** 开发者可能需要查看缓存的资源内容和响应头，以了解缓存了什么以及缓存策略是什么。
   ```bash
   cachetool ~/.config/chromium/Default/Cache blockfile get_stream https://example.com/script.js 1  # 查看内容
   cachetool ~/.config/chromium/Default/Cache blockfile get_stream https://example.com/script.js 0  # 查看响应头
   ```
   他们会检查 `Cache-Control`、`Expires` 等头部，确认缓存策略是否正确。

6. **使用 `delete_key` 删除缓存条目:** 如果开发者认为缓存了错误的资源版本，他们可以使用 `delete_key` 命令删除该资源的缓存。
   ```bash
   cachetool ~/.config/chromium/Default/Cache blockfile delete_key https://example.com/script.js
   ```

7. **使用 `update_raw_headers` 或 `set_header` 修改响应头 (谨慎使用):**  在某些情况下，开发者可能需要修改缓存的响应头来测试不同的缓存策略或修复错误的缓存头。
   ```bash
   # 获取当前的响应头
   cachetool ~/.config/chromium/Default/Cache blockfile get_stream https://example.com/script.js 0 > headers.txt
   # 编辑 headers.txt 文件，修改 Cache-Control
   cachetool ~/.config/chromium/Default/Cache blockfile update_raw_headers https://example.com/script.js < modified_headers.txt
   ```
   或者使用 `set_header` 单独设置某个头：
   ```bash
   cachetool ~/.config/chromium/Default/Cache blockfile set_header https://example.com/script.js Cache-Control "no-cache"
   ```
   **注意:** 修改缓存头是一种高级操作，需要谨慎使用，因为可能会导致不可预测的行为。

8. **验证结果:** 在执行上述操作后，开发者会重新加载网页，检查问题是否得到解决，资源是否已更新。

通过这些步骤，开发者可以使用 `cachetool` 作为强大的调试工具，深入了解和控制 Chromium 的磁盘缓存行为，从而诊断和解决与缓存相关的问题。

### 提示词
```
这是目录为net/tools/cachetool/cachetool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <iostream>
#include <memory>
#include <string_view>
#include <unordered_map>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/format_macros.h"
#include "base/hash/md5.h"
#include "base/logging.h"
#include "base/message_loop/message_pump_type.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/http/http_cache.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_util.h"

using disk_cache::Backend;
using disk_cache::BackendResult;
using disk_cache::Entry;
using disk_cache::EntryResult;

namespace {

struct EntryData {
  std::string url;
  std::string mime_type;
  int size;
};

constexpr int kResponseInfoIndex = 0;
constexpr int kResponseContentIndex = 1;

const char* const kCommandNames[] = {
    "stop",          "get_size",   "list_keys",          "get_stream",
    "delete_stream", "delete_key", "update_raw_headers", "list_dups",
    "set_header"};

// Prints the command line help.
void PrintHelp() {
  std::cout << "cachetool <cache_path> <cache_backend_type> <subcommand> "
            << std::endl
            << std::endl;
  std::cout << "Available cache backend types: simple, blockfile" << std::endl;
  std::cout << "Available subcommands:" << std::endl;
  std::cout << "  batch: Starts cachetool to process serialized commands "
            << "passed down by the standard input and return commands output "
            << "in the stdout until the stop command is received." << std::endl;
  std::cout << "  delete_key <key>: Delete key from cache." << std::endl;
  std::cout << "  delete_stream <key> <index>: Delete a particular stream of a"
            << " given key." << std::endl;
  std::cout << "  get_size: Calculate the total size of the cache in bytes."
            << std::endl;
  std::cout << "  get_stream <key> <index>: Print a particular stream for a"
            << " given key." << std::endl;
  std::cout << "  list_keys: List all keys in the cache." << std::endl;
  std::cout << "  list_dups: List all resources with duplicate bodies in the "
            << "cache." << std::endl;
  std::cout << "  update_raw_headers <key>: Update stdin as the key's raw "
            << "response headers." << std::endl;
  std::cout << "  set_header <key> <name> <value>: Set one of key's raw "
            << "response headers." << std::endl;
  std::cout << "  stop: Verify that the cache can be opened and return, "
            << "confirming the cache exists and is of the right type."
            << std::endl;
  std::cout << "Expected values of <index> are:" << std::endl;
  std::cout << "  0 (HTTP response headers)" << std::endl;
  std::cout << "  1 (transport encoded content)" << std::endl;
  std::cout << "  2 (compiled content)" << std::endl;
}

// Generic command input/output.
class CommandMarshal {
 public:
  explicit CommandMarshal(Backend* cache_backend)
      : cache_backend_(cache_backend) {}
  virtual ~CommandMarshal() = default;

  // Reads the next command's name to execute.
  virtual std::string ReadCommandName() = 0;

  // Reads the next parameter as an integer.
  virtual int ReadInt() = 0;

  // Reads the next parameter as stream index.
  int ReadStreamIndex() {
    if (has_failed())
      return -1;
    int index = ReadInt();
    if (index < 0 || index > 2) {
      ReturnFailure("Invalid stream index.");
      return -1;
    }
    return index;
  }

  // Reads the next parameter as a string.
  virtual std::string ReadString() = 0;

  // Reads the next parameter from stdin as string.
  virtual std::string ReadBufferedString() = 0;

  // Communicates back an integer.
  virtual void ReturnInt(int integer) = 0;

  // Communicates back a 64-bit integer.
  virtual void ReturnInt64(int64_t integer) = 0;

  // Communicates back a string.
  virtual void ReturnString(const std::string& string) = 0;

  // Communicates back a buffer.
  virtual void ReturnBuffer(net::GrowableIOBuffer* buffer) = 0;

  // Communicates back command failure.
  virtual void ReturnFailure(const std::string& error_msg) = 0;

  // Communicates back command success.
  virtual void ReturnSuccess() { DCHECK(!command_failed_); }

  // Returns whether the command has failed.
  inline bool has_failed() { return command_failed_; }

  // Returns the opened cache backend.
  Backend* cache_backend() { return cache_backend_; }

 protected:
  bool command_failed_ = false;
  Backend* const cache_backend_;
};

// Command line input/output that is user readable.
class ProgramArgumentCommandMarshal final : public CommandMarshal {
 public:
  ProgramArgumentCommandMarshal(Backend* cache_backend,
                                base::CommandLine::StringVector args)
      : CommandMarshal(cache_backend), command_line_args_(args) {}

  // Implements CommandMarshal.
  std::string ReadCommandName() override {
    if (args_id_ == 0)
      return ReadString();
    else if (args_id_ == command_line_args_.size())
      return "stop";
    else if (!has_failed())
      ReturnFailure("Command line arguments too long.");
    return "";
  }

  // Implements CommandMarshal.
  int ReadInt() override {
    std::string integer_str = ReadString();
    int integer = -1;
    if (!base::StringToInt(integer_str, &integer)) {
      ReturnFailure("Couldn't parse integer.");
      return 0;
    }
    return integer;
  }

  // Implements CommandMarshal.
  std::string ReadString() override {
    if (args_id_ < command_line_args_.size())
      return command_line_args_[args_id_++];
    if (!has_failed())
      ReturnFailure("Command line arguments too short.");
    return "";
  }

  // Implements CommandMarshal.
  std::string ReadBufferedString() override {
    std::ostringstream raw_headers_stream;
    for (std::string line; std::getline(std::cin, line);)
      raw_headers_stream << line << std::endl;
    return raw_headers_stream.str();
  }

  // Implements CommandMarshal.
  void ReturnInt(int integer) override {
    DCHECK(!has_failed());
    std::cout << integer << std::endl;
  }

  // Implements CommandMarshal.
  void ReturnInt64(int64_t integer) override {
    DCHECK(!has_failed());
    std::cout << integer << std::endl;
  }

  // Implements CommandMarshal.
  void ReturnString(const std::string& string) override {
    DCHECK(!has_failed());
    std::cout << string << std::endl;
  }

  // Implements CommandMarshal.
  void ReturnBuffer(net::GrowableIOBuffer* buffer) override {
    DCHECK(!has_failed());
    auto span = base::as_chars(buffer->span_before_offset());
    std::cout.write(span.data(), span.size());
  }

  // Implements CommandMarshal.
  void ReturnFailure(const std::string& error_msg) override {
    DCHECK(!has_failed());
    std::cerr << error_msg << std::endl;
    command_failed_ = true;
  }

 private:
  const base::CommandLine::StringVector command_line_args_;
  size_t args_id_ = 0;
};

// Online command input/output that receives pickled commands from stdin and
// returns their results back in stdout. Send the stop command to properly exit
// cachetool's main loop.
class StreamCommandMarshal final : public CommandMarshal {
 public:
  explicit StreamCommandMarshal(Backend* cache_backend)
      : CommandMarshal(cache_backend) {}

  // Implements CommandMarshal.
  std::string ReadCommandName() override {
    if (has_failed())
      return "";
    std::cout.flush();
    size_t command_id = static_cast<size_t>(std::cin.get());
    if (command_id >= std::size(kCommandNames)) {
      ReturnFailure("Unknown command.");
      return "";
    }
    return kCommandNames[command_id];
  }

  // Implements CommandMarshal.
  int ReadInt() override {
    if (has_failed())
      return -1;
    int integer = -1;
    std::cin.read(reinterpret_cast<char*>(&integer), sizeof(integer));
    return integer;
  }

  // Implements CommandMarshal.
  std::string ReadString() override {
    if (has_failed())
      return "";
    int string_size = ReadInt();
    if (string_size <= 0) {
      if (string_size < 0)
        ReturnFailure("Size of string is negative.");
      return "";
    }
    std::vector<char> tmp_buffer(string_size + 1);
    std::cin.read(tmp_buffer.data(), string_size);
    tmp_buffer[string_size] = 0;
    return std::string(tmp_buffer.data(), string_size);
  }

  // Implements CommandMarshal.
  std::string ReadBufferedString() override { return ReadString(); }

  // Implements CommandMarshal.
  void ReturnInt(int integer) override {
    DCHECK(!command_failed_);
    std::cout.write(reinterpret_cast<char*>(&integer), sizeof(integer));
  }

  // Implements CommandMarshal.
  void ReturnInt64(int64_t integer) override {
    DCHECK(!has_failed());
    std::cout.write(reinterpret_cast<char*>(&integer), sizeof(integer));
  }

  // Implements CommandMarshal.
  void ReturnString(const std::string& string) override {
    ReturnInt(string.size());
    std::cout.write(string.c_str(), string.size());
  }

  // Implements CommandMarshal.
  void ReturnBuffer(net::GrowableIOBuffer* buffer) override {
    ReturnInt(buffer->offset());
    auto span = base::as_chars(buffer->span_before_offset());
    std::cout.write(span.data(), span.size());
  }

  // Implements CommandMarshal.
  void ReturnFailure(const std::string& error_msg) override {
    ReturnString(error_msg);
    command_failed_ = true;
  }

  // Implements CommandMarshal.
  void ReturnSuccess() override { ReturnInt(0); }
};

// Gets the cache's size.
void GetSize(CommandMarshal* command_marshal) {
  net::TestInt64CompletionCallback cb;
  int64_t rv = command_marshal->cache_backend()->CalculateSizeOfAllEntries(
      cb.callback());
  rv = cb.GetResult(rv);
  if (rv < 0)
    return command_marshal->ReturnFailure("Couldn't get cache size.");
  command_marshal->ReturnSuccess();
  command_marshal->ReturnInt64(rv);
}

// Prints all of a cache's keys to stdout.
bool ListKeys(CommandMarshal* command_marshal) {
  std::unique_ptr<Backend::Iterator> entry_iterator =
      command_marshal->cache_backend()->CreateIterator();
  TestEntryResultCompletionCallback cb;
  EntryResult result = entry_iterator->OpenNextEntry(cb.callback());
  command_marshal->ReturnSuccess();
  while ((result = cb.GetResult(std::move(result))).net_error() == net::OK) {
    Entry* entry = result.ReleaseEntry();
    std::string url = entry->GetKey();
    command_marshal->ReturnString(url);
    entry->Close();
    result = entry_iterator->OpenNextEntry(cb.callback());
  }
  command_marshal->ReturnString("");
  return true;
}

bool GetResponseInfoForEntry(disk_cache::Entry* entry,
                             net::HttpResponseInfo* response_info) {
  int size = entry->GetDataSize(kResponseInfoIndex);
  if (size == 0)
    return false;
  scoped_refptr<net::IOBuffer> buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(size);
  net::TestCompletionCallback cb;

  int bytes_read = 0;
  while (true) {
    int rv = entry->ReadData(kResponseInfoIndex, bytes_read, buffer.get(), size,
                             cb.callback());
    rv = cb.GetResult(rv);
    if (rv < 0) {
      entry->Close();
      return false;
    }

    if (rv == 0) {
      bool truncated_response_info = false;
      if (!net::HttpCache::ParseResponseInfo(buffer->span(), response_info,
                                             &truncated_response_info)) {
        return false;
      }
      return !truncated_response_info;
    }

    bytes_read += rv;
  }

  NOTREACHED();
}

std::string GetMD5ForResponseBody(disk_cache::Entry* entry) {
  if (entry->GetDataSize(kResponseContentIndex) == 0)
    return "";

  const int kInitBufferSize = 80 * 1024;
  scoped_refptr<net::IOBuffer> buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kInitBufferSize);
  net::TestCompletionCallback cb;

  base::MD5Context ctx;
  base::MD5Init(&ctx);

  int bytes_read = 0;
  while (true) {
    int rv = entry->ReadData(kResponseContentIndex, bytes_read, buffer.get(),
                             kInitBufferSize, cb.callback());
    rv = cb.GetResult(rv);
    if (rv < 0) {
      entry->Close();
      return "";
    }

    if (rv == 0) {
      base::MD5Digest digest;
      base::MD5Final(&digest, &ctx);
      return base::MD5DigestToBase16(digest);
    }

    bytes_read += rv;
    base::MD5Update(&ctx, std::string_view(buffer->data(), rv));
  }

  NOTREACHED();
}

void PersistResponseInfo(CommandMarshal* command_marshal,
                         const std::string& key,
                         const net::HttpResponseInfo& response_info) {
  scoped_refptr<net::PickledIOBuffer> data =
      base::MakeRefCounted<net::PickledIOBuffer>();
  response_info.Persist(data->pickle(), false, false);
  data->Done();

  TestEntryResultCompletionCallback cb_open;
  EntryResult result = command_marshal->cache_backend()->OpenEntry(
      key, net::HIGHEST, cb_open.callback());
  result = cb_open.GetResult(std::move(result));
  CHECK_EQ(result.net_error(), net::OK);
  Entry* cache_entry = result.ReleaseEntry();

  int data_len = data->pickle()->size();
  net::TestCompletionCallback cb;
  int rv = cache_entry->WriteData(kResponseInfoIndex, 0, data.get(), data_len,
                                  cb.callback(), true);
  if (cb.GetResult(rv) != data_len)
    return command_marshal->ReturnFailure("Couldn't write headers.");
  command_marshal->ReturnSuccess();
  cache_entry->Close();
}

void ListDups(CommandMarshal* command_marshal) {
  std::unique_ptr<Backend::Iterator> entry_iterator =
      command_marshal->cache_backend()->CreateIterator();
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result = entry_iterator->OpenNextEntry(cb.callback());
  command_marshal->ReturnSuccess();

  std::unordered_map<std::string, std::vector<EntryData>> md5_entries;

  int total_entries = 0;

  while ((result = cb.GetResult(std::move(result))).net_error() == net::OK) {
    Entry* entry = result.ReleaseEntry();
    total_entries += 1;
    net::HttpResponseInfo response_info;
    if (!GetResponseInfoForEntry(entry, &response_info)) {
      entry->Close();
      entry = nullptr;
      result = entry_iterator->OpenNextEntry(cb.callback());
      continue;
    }

    std::string hash = GetMD5ForResponseBody(entry);
    if (hash.empty()) {
      // Sparse entries and empty bodies are skipped.
      entry->Close();
      entry = nullptr;
      result = entry_iterator->OpenNextEntry(cb.callback());
      continue;
    }

    EntryData entry_data;

    entry_data.url = entry->GetKey();
    entry_data.size = entry->GetDataSize(kResponseContentIndex);
    if (response_info.headers)
      response_info.headers->GetMimeType(&entry_data.mime_type);

    auto iter = md5_entries.find(hash);
    if (iter == md5_entries.end()) {
      md5_entries.emplace(hash, std::vector<EntryData>{entry_data});
    } else {
      iter->second.push_back(entry_data);
    }

    entry->Close();
    entry = nullptr;
    result = entry_iterator->OpenNextEntry(cb.callback());
  }

  // Print the duplicates and collect stats.
  int total_duped_entries = 0;
  int64_t total_duped_bytes = 0u;
  for (const auto& hash_and_entries : md5_entries) {
    if (hash_and_entries.second.size() == 1)
      continue;

    int dups = hash_and_entries.second.size() - 1;
    total_duped_entries += dups;
    total_duped_bytes += hash_and_entries.second[0].size * dups;

    for (const auto& entry : hash_and_entries.second) {
      std::string out = base::StringPrintf(
          "%d, %s, %s", entry.size, entry.url.c_str(), entry.mime_type.c_str());
      command_marshal->ReturnString(out);
    }
  }

  // Print the stats.
  net::TestInt64CompletionCallback size_cb;
  int64_t rv = command_marshal->cache_backend()->CalculateSizeOfAllEntries(
      size_cb.callback());
  rv = size_cb.GetResult(rv);
  LOG(ERROR) << "Wasted bytes = " << total_duped_bytes;
  LOG(ERROR) << "Wasted entries = " << total_duped_entries;
  LOG(ERROR) << "Total entries = " << total_entries;
  LOG(ERROR) << "Cache size = " << rv;
  LOG(ERROR) << "Percentage of cache wasted = " << total_duped_bytes * 100 / rv;
}

// Gets a key's stream to a buffer.
scoped_refptr<net::GrowableIOBuffer> GetStreamForKeyBuffer(
    CommandMarshal* command_marshal,
    const std::string& key,
    int index) {
  DCHECK(!command_marshal->has_failed());

  TestEntryResultCompletionCallback cb_open;
  EntryResult result = command_marshal->cache_backend()->OpenEntry(
      key, net::HIGHEST, cb_open.callback());
  result = cb_open.GetResult(std::move(result));
  if (result.net_error() != net::OK) {
    command_marshal->ReturnFailure("Couldn't find key's entry.");
    return nullptr;
  }
  Entry* cache_entry = result.ReleaseEntry();

  const int kInitBufferSize = 8192;
  scoped_refptr<net::GrowableIOBuffer> buffer =
      base::MakeRefCounted<net::GrowableIOBuffer>();
  buffer->SetCapacity(kInitBufferSize);
  net::TestCompletionCallback cb;
  while (true) {
    int rv = cache_entry->ReadData(index, buffer->offset(), buffer.get(),
                                   buffer->capacity() - buffer->offset(),
                                   cb.callback());
    rv = cb.GetResult(rv);
    if (rv < 0) {
      cache_entry->Close();
      command_marshal->ReturnFailure("Stream read error.");
      return nullptr;
    }
    buffer->set_offset(buffer->offset() + rv);
    if (rv == 0)
      break;
    buffer->SetCapacity(buffer->offset() * 2);
  }
  cache_entry->Close();
  return buffer;
}

// Prints a key's stream to stdout.
void GetStreamForKey(CommandMarshal* command_marshal) {
  std::string key = command_marshal->ReadString();
  int index = command_marshal->ReadInt();
  if (command_marshal->has_failed())
    return;
  scoped_refptr<net::GrowableIOBuffer> buffer(
      GetStreamForKeyBuffer(command_marshal, key, index));
  if (command_marshal->has_failed())
    return;
  if (index == kResponseInfoIndex) {
    net::HttpResponseInfo response_info;
    bool truncated_response_info = false;
    if (!net::HttpCache::ParseResponseInfo(buffer->span_before_offset(),
                                           &response_info,
                                           &truncated_response_info)) {
      // This can happen when reading data stored by content::CacheStorage.
      std::cerr << "WARNING: Returning empty response info for key: " << key
                << std::endl;
      command_marshal->ReturnSuccess();
      return command_marshal->ReturnString("");
    }
    if (truncated_response_info)
      std::cerr << "WARNING: Truncated HTTP response." << std::endl;
    command_marshal->ReturnSuccess();
    command_marshal->ReturnString(
        net::HttpUtil::ConvertHeadersBackToHTTPResponse(
            response_info.headers->raw_headers()));
  } else {
    command_marshal->ReturnSuccess();
    command_marshal->ReturnBuffer(buffer.get());
  }
}

// Sets stdin as the key's raw response headers.
void UpdateRawResponseHeaders(CommandMarshal* command_marshal) {
  std::string key = command_marshal->ReadString();
  std::string raw_headers = command_marshal->ReadBufferedString();
  if (command_marshal->has_failed())
    return;
  scoped_refptr<net::GrowableIOBuffer> buffer(
      GetStreamForKeyBuffer(command_marshal, key, kResponseInfoIndex));
  if (command_marshal->has_failed())
    return;
  net::HttpResponseInfo response_info;
  bool truncated_response_info = false;
  net::HttpCache::ParseResponseInfo(buffer->span_before_offset(),
                                    &response_info, &truncated_response_info);
  if (truncated_response_info)
    std::cerr << "WARNING: Truncated HTTP response." << std::endl;

  response_info.headers =
      base::MakeRefCounted<net::HttpResponseHeaders>(raw_headers);
  PersistResponseInfo(command_marshal, key, response_info);
}

// Sets a response header for a key.
void SetHeader(CommandMarshal* command_marshal) {
  std::string key = command_marshal->ReadString();
  std::string header_name = command_marshal->ReadString();
  std::string header_value = command_marshal->ReadString();
  if (command_marshal->has_failed())
    return;

  // Open the existing entry.
  scoped_refptr<net::GrowableIOBuffer> buffer(
      GetStreamForKeyBuffer(command_marshal, key, kResponseInfoIndex));
  if (command_marshal->has_failed())
    return;

  // Read the entry into |response_info|.
  net::HttpResponseInfo response_info;
  bool truncated_response_info = false;
  if (!net::HttpCache::ParseResponseInfo(buffer->span_before_offset(),
                                         &response_info,
                                         &truncated_response_info)) {
    command_marshal->ReturnFailure("Couldn't read response info");
    return;
  }
  if (truncated_response_info)
    std::cerr << "WARNING: Truncated HTTP response." << std::endl;

  // Update the header.
  response_info.headers->SetHeader(header_name, header_value);

  // Write the entry.
  PersistResponseInfo(command_marshal, key, response_info);
}

// Deletes a specified key stream from the cache.
void DeleteStreamForKey(CommandMarshal* command_marshal) {
  std::string key = command_marshal->ReadString();
  int index = command_marshal->ReadInt();
  if (command_marshal->has_failed())
    return;

  TestEntryResultCompletionCallback cb_open;
  EntryResult result = command_marshal->cache_backend()->OpenEntry(
      key, net::HIGHEST, cb_open.callback());
  result = cb_open.GetResult(std::move(result));
  if (result.net_error() != net::OK)
    return command_marshal->ReturnFailure("Couldn't find key's entry.");
  Entry* cache_entry = result.ReleaseEntry();

  net::TestCompletionCallback cb;
  scoped_refptr<net::StringIOBuffer> buffer =
      base::MakeRefCounted<net::StringIOBuffer>("");
  int rv =
      cache_entry->WriteData(index, 0, buffer.get(), 0, cb.callback(), true);
  if (cb.GetResult(rv) != net::OK)
    return command_marshal->ReturnFailure("Couldn't delete key stream.");
  command_marshal->ReturnSuccess();
  cache_entry->Close();
}

// Deletes a specified key from the cache.
void DeleteKey(CommandMarshal* command_marshal) {
  std::string key = command_marshal->ReadString();
  if (command_marshal->has_failed())
    return;
  net::TestCompletionCallback cb;
  int rv = command_marshal->cache_backend()->DoomEntry(key, net::HIGHEST,
                                                       cb.callback());
  if (cb.GetResult(rv) != net::OK)
    command_marshal->ReturnFailure("Couldn't delete key.");
  else
    command_marshal->ReturnSuccess();
}

// Executes all command from the |command_marshal|.
bool ExecuteCommands(CommandMarshal* command_marshal) {
  while (!command_marshal->has_failed()) {
    std::string subcommand(command_marshal->ReadCommandName());
    if (command_marshal->has_failed())
      break;
    if (subcommand == "stop") {
      command_marshal->ReturnSuccess();
      return true;
    } else if (subcommand == "batch") {
      StreamCommandMarshal stream_command_marshal(
          command_marshal->cache_backend());
      return ExecuteCommands(&stream_command_marshal);
    } else if (subcommand == "delete_key") {
      DeleteKey(command_marshal);
    } else if (subcommand == "delete_stream") {
      DeleteStreamForKey(command_marshal);
    } else if (subcommand == "get_size") {
      GetSize(command_marshal);
    } else if (subcommand == "get_stream") {
      GetStreamForKey(command_marshal);
    } else if (subcommand == "list_keys") {
      ListKeys(command_marshal);
    } else if (subcommand == "update_raw_headers") {
      UpdateRawResponseHeaders(command_marshal);
    } else if (subcommand == "set_header") {
      SetHeader(command_marshal);
    } else if (subcommand == "list_dups") {
      ListDups(command_marshal);
    } else {
      // The wrong subcommand is originated from the command line.
      command_marshal->ReturnFailure("Unknown command.");
      PrintHelp();
    }
  }
  return false;
}

}  // namespace

int main(int argc, char* argv[]) {
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor io_task_executor(base::MessagePumpType::IO);
  base::CommandLine::Init(argc, argv);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  base::CommandLine::StringVector args = command_line.GetArgs();
  if (args.size() < 3U) {
    PrintHelp();
    return 1;
  }

  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("cachetool");

  base::FilePath cache_path(args[0]);
  std::string cache_backend_type(args[1]);

  net::BackendType backend_type;
  if (cache_backend_type == "simple") {
    backend_type = net::CACHE_BACKEND_SIMPLE;
  } else if (cache_backend_type == "blockfile") {
    backend_type = net::CACHE_BACKEND_BLOCKFILE;
  } else {
    std::cerr << "Unknown cache type." << std::endl;
    PrintHelp();
    return 1;
  }

  TestBackendResultCompletionCallback cb;
  BackendResult result = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, backend_type, /*file_operations=*/nullptr, cache_path,
      INT_MAX, disk_cache::ResetHandling::kNeverReset, /*net_log=*/nullptr,
      cb.callback());
  result = cb.GetResult(std::move(result));
  if (result.net_error != net::OK) {
    std::cerr << "Invalid cache." << std::endl;
    return 1;
  }
  std::unique_ptr<Backend> cache_backend = std::move(result.backend);

  ProgramArgumentCommandMarshal program_argument_marshal(
      cache_backend.get(),
      base::CommandLine::StringVector(args.begin() + 2, args.end()));
  bool successful_commands = ExecuteCommands(&program_argument_marshal);

  base::RunLoop().RunUntilIdle();
  cache_backend = nullptr;
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();
  return !successful_commands;
}
```