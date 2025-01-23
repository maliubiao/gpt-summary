Response:
The user wants a summary of the C code provided, which implements a simple DNS resolver cache in Android's Bionic libc. Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The comments at the beginning clearly state the purpose: a small, simple DNS resolver cache. It stores DNS query-answer pairs to reduce DNS traffic.

2. **Key Design Principles:**  The comments emphasize the simplicity of the design. This is a crucial point to highlight in the summary. Specifically mention:
    * Raw packet input/output.
    * Smallest TTL for expiration.
    * Simple hash table with LRU.
    * The intention of a future, more comprehensive DNS cache.

3. **API Overview:** The comments detail the API functions. List these and their roles:
    * `_resolv_cache_get()`: Obtain a cache handle (initializes the cache).
    * `_resolv_cache_lookup()`: Check the cache before a query. Note the return values: `FOUND`, `NOTFOUND`, `UNSUPPORTED`.
    * `_resolv_cache_add()`: Add a received answer to the cache.

4. **Configuration Parameter:**  The `CONFIG_MAX_ENTRIES` macro is defined and explained. Mention its purpose and how the value was determined (though the historical context is less critical for a functional summary). Emphasize it's the maximum number of entries.

5. **Debugging Features:** Note the `DEBUG` and `DEBUG_DATA` macros and their effect on logging.

6. **Helper Functions:**  The code includes a set of helper functions, especially for bounded buffer manipulation (`_bprint_*`). Group these under a common theme. Also, acknowledge the DNS packet manipulation and analysis functions (`_dnsPacket_*`).

7. **Core Data Structures:** Identify the `Entry` struct as the fundamental unit of the cache, noting its members (hash, links, query/answer data, expiration, etc.).

8. **TTL Handling:**  The code has functions to determine the TTL of an answer. Highlight `answer_getTTL` and `answer_getNegativeTTL` as important aspects of cache management.

9. **Structure and Flow:**  The code is structured around handling DNS query and answer packets. Mention the processes of checking, hashing, and comparing queries.

10. **Omit Implementation Details (For a High-Level Summary):**  Avoid going into the nitty-gritty of the FNV hash function, the exact bit manipulation for DNS flags, or the intricacies of DNS name compression (beyond acknowledging it exists). The goal is a *functional* summary, not a detailed code walkthrough.

11. **Address the "Part 1" Request:** Explicitly state that this is a summary of the functionality, in response to the user's "Part 1" instruction.

12. **Language and Tone:** Use clear, concise language. Avoid overly technical jargon where possible. Maintain a neutral and informative tone.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Simply list all the functions.
* **Correction:**  Group functions by their purpose (API, debugging, DNS packet handling, etc.) for better organization and understanding.
* **Initial thought:**  Explain the DNS packet format in detail.
* **Correction:** Briefly mention the key components (header, question, answer, etc.) and focus on the purpose of the `_dnsPacket_*` functions (checking, hashing, comparing). The user asked for functionality, not a DNS protocol lesson.
* **Initial thought:** Go deep into the hash table and LRU implementation.
* **Correction:**  Mention the hash table and LRU as core concepts but avoid detailed implementation explanations, as the code itself isn't provided for those specific data structures in this snippet. The `Entry` structure gives enough information for a functional understanding.
* **Ensure clarity on "simple":** Continuously emphasize that this is a *simple* cache, aligning with the comments in the code.

By following these steps, the generated summary effectively captures the essential functionality of the provided code snippet.
这个C源代码文件 `bionic/libc/dns/resolv/res_cache.c` 实现了 Android Bionic C 库中 DNS 解析器的缓存功能。

**它的主要功能可以归纳为：**

1. **DNS 查询结果缓存：** 该文件实现了一个简单的内存 DNS 缓存，用于存储 DNS 查询的答案。 这有助于减少重复的 DNS 查询，从而提高网络性能并降低 DNS 服务器的负载。

2. **优化 DNS 查询：** 在进行 DNS 查询之前，客户端会先查找缓存。如果找到了匹配的答案，则直接使用缓存中的结果，而无需向 DNS 服务器发送实际的查询请求。

3. **基于 TTL 的过期机制：** 缓存中的每个条目都有一个生存时间（TTL）。条目在 TTL 到期后会被标记为无效，并在下次查找时被忽略或删除。TTL 的值取自 DNS 响应中所有记录的最小 TTL。

4. **简单的哈希表实现：**  缓存使用一个简单的哈希表来实现，以便快速查找。哈希键基于原始的 DNS 查询数据。

5. **最近最少使用（LRU）过期策略：** 当缓存已满时，最近最少使用的条目会被优先删除，以便为新的缓存条目腾出空间。

6. **支持 IPv4 和 IPv6：** 缓存可以存储 IPv4 (A 记录) 和 IPv6 (AAAA 记录) 的 DNS 查询结果。

7. **处理否定响应：**  即使 DNS 查询没有找到结果（否定响应），缓存也可以存储这些否定响应的 TTL 信息，以避免在短时间内重复查询相同的域名。

**与 Android 功能的关系举例说明：**

* **应用程序域名解析加速：** 当 Android 应用程序需要连接到某个域名时（例如，下载图片或访问 API），libc 的 DNS 解析器会被调用。`res_cache.c` 提供的缓存功能可以显著加快后续对相同域名的访问速度。例如，一个应用首次访问 `www.google.com` 可能需要进行 DNS 查询，但后续的访问很可能直接从缓存中获取 IP 地址，速度更快。

* **系统级缓存：** 该缓存是系统级的，这意味着所有使用 Bionic libc 的进程都可以共享这个缓存。这提高了缓存的效率，因为不同应用对相同域名的查询可以互相受益。

* **网络连接优化：**  在移动网络环境下，减少 DNS 查询的数量可以节省移动数据流量，并可能延长设备的电池寿命。

**详细解释每一个 libc 函数的功能是如何实现的：**

由于您只提供了 `res_cache.c` 的源代码，并没有提供其他相关文件（例如，哈希表和 LRU 链表的实现），因此无法详细解释所有涉及的 libc 函数的实现。但是，我们可以根据代码中的调用推断一些关键函数的用途：

* **`_resolv_cache_get()`:**  这个函数负责获取 DNS 缓存的句柄。它可能包含初始化缓存的操作，例如分配内存、初始化哈希表和 LRU 链表。如果缓存被禁用，则返回 NULL。

* **`_resolv_cache_lookup(const uint8_t* query, int querylen, uint8_t* answer, int* answerlen)`:** 这是缓存查找的核心函数。
    1. **计算查询哈希：**  对输入的原始 DNS 查询数据 `query` 计算哈希值。
    2. **查找哈希表：** 使用计算出的哈希值在哈希表中查找匹配的缓存条目。
    3. **比较查询数据：** 如果找到匹配的哈希值，还需要比较缓存条目中的原始查询数据和输入的 `query`，因为不同的查询可能产生相同的哈希值（哈希冲突）。
    4. **检查 TTL：** 如果找到完全匹配的条目，则检查该条目的过期时间 `expires` 是否晚于当前时间。
    5. **返回结果：**
        * `RESOLV_CACHE_FOUND`：找到有效的缓存条目，将缓存的答案数据复制到 `answer` 缓冲区，并更新 `answerlen`。
        * `RESOLV_CACHE_NOTFOUND`：没有找到匹配的缓存条目或找到的条目已过期。
        * `RESOLV_CACHE_UNSUPPORTED`：  查询类型不受支持（尽管代码中看似支持 A、PTR、MX、AAAA 和 ALL 类型），或者提供的 `answer` 缓冲区太小，无法容纳缓存的答案。

* **`_resolv_cache_add(const uint8_t* query, int querylen, const uint8_t* answer, int answerlen)`:** 这个函数用于将新的 DNS 查询结果添加到缓存中。
    1. **检查查询类型：**  检查查询是否是受支持的类型。
    2. **计算 TTL：** 调用 `answer_getTTL` 函数解析 DNS 响应，提取答案记录中的最小 TTL，或者从 SOA 记录中获取否定响应的 TTL。
    3. **创建缓存条目：** 分配内存创建一个新的 `Entry` 结构。
    4. **复制数据：** 将 `query` 和 `answer` 数据复制到新的缓存条目中。
    5. **设置过期时间：** 根据当前时间和计算出的 TTL 设置 `expires` 字段。
    6. **插入哈希表和 LRU 链表：** 将新的缓存条目插入到哈希表中对应的桶（bucket）中，并将其添加到 LRU 链表的头部，表示最近使用。
    7. **处理缓存满的情况：** 如果缓存已满（达到 `CONFIG_MAX_ENTRIES`），则从 LRU 链表的尾部移除最久未使用的条目，并从哈希表中删除。

* **`answer_getTTL(const void* answer, int answerlen)`:**  解析 DNS 响应包 `answer`，提取答案记录中的最小 TTL 值。如果响应是否定响应（没有答案记录），则返回 0。  这个函数使用了 `<resolv.h>` 中提供的 `ns_initparse` 和 `ns_parserr` 等函数来解析 DNS 消息结构，遍历答案记录，并获取每个记录的 TTL。

* **`answer_getNegativeTTL(ns_msg handle)`:**  专门用于处理否定 DNS 响应。它解析权威部分（Authority section）的 SOA (Start of Authority) 记录，并返回 SOA 记录中的 TTL 和 MINIMUM-TTL 字段的最小值。这是根据 RFC 2308 的规定来确定否定响应的缓存时间。

**对于涉及 dynamic linker 的功能：**

这个文件主要关注 DNS 缓存逻辑，并没有直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 负责在程序运行时加载和链接共享库 (`.so` 文件)。

**so 布局样本：**

假设一个应用程序使用了 libc 的 DNS 解析功能，其进程的内存布局中会包含 `libc.so`：

```
Memory Map:
...
address_range  perms    offset   dev   inode   pathname
...
0000007b4000-0000007b5700 r--p  00000000 103:07  /apex/com.android.runtime/lib64/bionic/libc.so
0000007b5700-0000007b7000 r-xp  00017000 103:07  /apex/com.android.runtime/lib64/bionic/libc.so
0000007b7000-0000007b9100 r--p  00030000 103:07  /apex/com.android.runtime/lib64/bionic/libc.so
0000007b9100-0000007b9200 r--p  00050000 103:07  /apex/com.android.runtime/lib64/bionic/libc.so
0000007b9200-0000007b9400 rw-p  00051000 103:07  /apex/com.android.runtime/lib64/bionic/libc.so
...
```

* **r--p (Read-only, private):**  代码段和只读数据段。
* **r-xp (Read-execute, private):**  可执行代码段。
* **rw-p (Read-write, private):**  可读写数据段 (例如，全局变量)。

**链接的处理过程：**

1. **编译时：** 当应用程序代码调用诸如 `getaddrinfo()` 这样的 DNS 解析函数时，编译器会将这些函数调用链接到 `libc.so` 中相应的符号。
2. **加载时：** 当应用程序启动时，dynamic linker (`linker64` 或 `linker`) 会加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析：** Dynamic linker 会解析应用程序中对 `libc.so` 中 DNS 相关函数的引用，并将这些引用指向 `libc.so` 中函数的实际地址。
4. **运行时调用：**  当应用程序执行到 DNS 解析相关的代码时，实际上会调用 `libc.so` 中实现的函数，而 `res_cache.c` 中的代码是这些函数实现的一部分。

**逻辑推理，假设输入与输出：**

**假设输入：**

* 缓存为空。
* 应用程序发起对 `www.example.com` 的 IPv4 (A 记录) 查询。
* 查询数据 (query): 一段包含 DNS 查询包的二进制数据。
* DNS 服务器返回 `www.example.com` 的 IPv4 地址为 `93.184.216.34`，TTL 为 300 秒。
* 响应数据 (answer): 一段包含 DNS 响应包的二进制数据。

**输出：**

1. **`_resolv_cache_lookup()`:**  由于缓存为空，返回 `RESOLV_CACHE_NOTFOUND`。
2. **实际 DNS 查询：**  libc 会将查询发送到配置的 DNS 服务器。
3. **`_resolv_cache_add()`:**  接收到 DNS 响应后，`_resolv_cache_add()` 被调用。
    * 解析响应，提取 TTL 为 300 秒。
    * 创建一个新的缓存条目，包含原始查询数据、响应数据和过期时间 (当前时间 + 300 秒)。
    * 将该条目添加到缓存的哈希表和 LRU 链表中。

**假设输入（第二次查询）：**

* 应用程序再次发起对 `www.example.com` 的 IPv4 查询 (相同的查询数据)。

**输出：**

1. **`_resolv_cache_lookup()`:**
    * 计算查询的哈希值。
    * 在哈希表中找到匹配的条目。
    * 比较原始查询数据，确认匹配。
    * 检查 TTL，假设尚未过期。
    * 返回 `RESOLV_CACHE_FOUND`，并将缓存的响应数据复制到应用程序提供的缓冲区。

**用户或编程常见的使用错误：**

* **错误的缓冲区大小：** 在调用 `_resolv_cache_lookup()` 时，如果提供的 `answer` 缓冲区太小，无法容纳缓存的 DNS 响应，函数会返回 `RESOLV_CACHE_UNSUPPORTED`。开发者需要确保缓冲区足够大。

* **不理解缓存的行为：** 开发者可能错误地认为 DNS 缓存是永久的。他们需要理解 TTL 的概念，知道缓存的条目会过期。

* **手动操作缓存（通常不应该）：**  应用程序通常不需要直接调用 `_resolv_cache_lookup()` 或 `_resolv_cache_add()`。这些函数是 libc 内部使用的。直接操作可能导致数据不一致或其他问题。

**说明 Android framework or ndk 是如何一步步的到达这里：**

1. **Android Framework/NDK 调用 DNS 解析函数：**
   * **Android Framework (Java 代码):** 当应用程序使用 `java.net.InetAddress.getByName()` 或 `java.net.URL` 等类进行网络操作时，这些类最终会调用到 Android 系统库中的本地方法。
   * **NDK (C/C++ 代码):** NDK 应用可以直接调用 libc 提供的 DNS 解析函数，例如 `getaddrinfo()`, `gethostbyname()`, `gethostbyname2()`, 等。

2. **libc 的 DNS 解析函数 (`getaddrinfo` 等)：**  这些函数是 Bionic libc 中提供的标准 C 库函数，用于执行 DNS 查询。

3. **`res_send()` 或类似函数：**  libc 的 DNS 解析函数内部会调用更底层的函数（例如 `res_send()` 或其内部调用的函数）来构建 DNS 查询报文，并通过网络发送到配置的 DNS 服务器。

4. **`_resolv_cache_lookup()` 调用：** 在真正发送 DNS 查询之前，libc 的 DNS 解析函数会首先调用 `_resolv_cache_lookup()` 来检查缓存中是否存在答案。

5. **缓存命中或未命中：**
   * **缓存命中 (`RESOLV_CACHE_FOUND`)：**  从缓存中获取答案，跳过实际的 DNS 查询过程。
   * **缓存未命中 (`RESOLV_CACHE_NOTFOUND`)：**  继续进行 DNS 查询，发送请求到 DNS 服务器。

6. **接收 DNS 响应：**  接收到 DNS 服务器的响应后，libc 会解析响应数据。

7. **`_resolv_cache_add()` 调用：**  如果响应是有效的，libc 的 DNS 解析函数会调用 `_resolv_cache_add()` 将查询和响应添加到缓存中。

8. **返回结果：**  最终，DNS 解析函数将结果（IP 地址等）返回给调用它的 Android Framework 或 NDK 代码。

**Frida Hook 示例调试步骤：**

可以使用 Frida Hook 来观察 `_resolv_cache_lookup` 和 `_resolv_cache_add` 的调用，以及缓存的命中和未命中情况。

```javascript
// Frida 脚本示例

// Hook _resolv_cache_lookup
Interceptor.attach(Module.findExportByName("libc.so", "_resolv_cache_lookup"), {
  onEnter: function (args) {
    console.log("[_resolv_cache_lookup] Entered");
    this.query = Memory.readByteArray(args[0], args[1].toInt());
    console.log("  Query Data:", hexdump(this.query, { length: args[1].toInt() }));
  },
  onLeave: function (retval) {
    console.log("[_resolv_cache_lookup] Left, Return Value:", retval);
    if (retval == 0) {
      console.log("  Cache NOT FOUND");
    } else if (retval == 1) {
      console.log("  Cache FOUND");
      var answerLenPtr = this.context.sp.add(8 * 3); // 假设 answerlen 指针在栈上的位置
      var answerLen = Memory.readS32(answerLenPtr);
      var answerPtr = this.context.sp.add(8 * 2); // 假设 answer 指针在栈上的位置
      var answer = Memory.readByteArray(Memory.readPointer(answerPtr), answerLen);
      console.log("  Answer Data:", hexdump(answer, { length: answerLen }));
    } else if (retval == 2) {
      console.log("  Cache UNSUPPORTED");
    }
  }
});

// Hook _resolv_cache_add
Interceptor.attach(Module.findExportByName("libc.so", "_resolv_cache_add"), {
  onEnter: function (args) {
    console.log("[_resolv_cache_add] Entered");
    this.query = Memory.readByteArray(args[0], args[1].toInt());
    console.log("  Query Data:", hexdump(this.query, { length: args[1].toInt() }));
    this.answer = Memory.readByteArray(args[2], args[3].toInt());
    console.log("  Answer Data:", hexdump(this.answer, { length: args[3].toInt() }));
  }
});
```

**使用步骤：**

1. **准备 Frida 环境：** 确保已安装 Frida 和 Frida-tools，并且目标 Android 设备已 root 并运行了 Frida 服务。
2. **编写 Frida 脚本：** 将上面的 JavaScript 代码保存到一个文件中（例如 `dns_cache_hook.js`）。
3. **运行 Frida 脚本：** 使用 `frida` 命令连接到目标应用程序的进程，并加载脚本：
   ```bash
   frida -U -f <your_app_package_name> -l dns_cache_hook.js --no-pause
   ```
   或者，如果目标进程已经在运行：
   ```bash
   frida -U <your_app_package_name> -l dns_cache_hook.js
   ```
4. **执行网络操作：** 在目标应用程序中执行会触发 DNS 查询的网络操作（例如，访问一个网站）。
5. **观察输出：**  Frida 控制台会打印出 `_resolv_cache_lookup` 和 `_resolv_cache_add` 函数的调用信息，包括查询和响应数据，以及缓存的命中/未命中状态。

**总结（归纳功能）：**

`bionic/libc/dns/resolv/res_cache.c` 文件实现了 Android Bionic libc 中 DNS 解析器的本地缓存功能。它通过存储 DNS 查询的答案，基于 TTL 进行过期管理，并采用简单的哈希表和 LRU 策略，来优化 DNS 查询性能，减少网络流量，并加速应用程序的网络连接。其核心功能在于在进行实际 DNS 查询之前检查缓存，并在接收到新的 DNS 响应后更新缓存。

### 提示词
```
这是目录为bionic/libc/dns/resolv/res_cache.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "resolv_cache.h"

#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pthread.h"

#include <errno.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if.h>

#include <arpa/inet.h>
#include "resolv_private.h"
#include "resolv_netid.h"
#include "res_private.h"

#include <async_safe/log.h>

/* This code implements a small and *simple* DNS resolver cache.
 *
 * It is only used to cache DNS answers for a time defined by the smallest TTL
 * among the answer records in order to reduce DNS traffic. It is not supposed
 * to be a full DNS cache, since we plan to implement that in the future in a
 * dedicated process running on the system.
 *
 * Note that its design is kept simple very intentionally, i.e.:
 *
 *  - it takes raw DNS query packet data as input, and returns raw DNS
 *    answer packet data as output
 *
 *    (this means that two similar queries that encode the DNS name
 *     differently will be treated distinctly).
 *
 *    the smallest TTL value among the answer records are used as the time
 *    to keep an answer in the cache.
 *
 *    this is bad, but we absolutely want to avoid parsing the answer packets
 *    (and should be solved by the later full DNS cache process).
 *
 *  - the implementation is just a (query-data) => (answer-data) hash table
 *    with a trivial least-recently-used expiration policy.
 *
 * Doing this keeps the code simple and avoids to deal with a lot of things
 * that a full DNS cache is expected to do.
 *
 * The API is also very simple:
 *
 *   - the client calls _resolv_cache_get() to obtain a handle to the cache.
 *     this will initialize the cache on first usage. the result can be NULL
 *     if the cache is disabled.
 *
 *   - the client calls _resolv_cache_lookup() before performing a query
 *
 *     if the function returns RESOLV_CACHE_FOUND, a copy of the answer data
 *     has been copied into the client-provided answer buffer.
 *
 *     if the function returns RESOLV_CACHE_NOTFOUND, the client should perform
 *     a request normally, *then* call _resolv_cache_add() to add the received
 *     answer to the cache.
 *
 *     if the function returns RESOLV_CACHE_UNSUPPORTED, the client should
 *     perform a request normally, and *not* call _resolv_cache_add()
 *
 *     note that RESOLV_CACHE_UNSUPPORTED is also returned if the answer buffer
 *     is too short to accomodate the cached result.
 */

/* default number of entries kept in the cache. This value has been
 * determined by browsing through various sites and counting the number
 * of corresponding requests. Keep in mind that our framework is currently
 * performing two requests per name lookup (one for IPv4, the other for IPv6)
 *
 *    www.google.com      4
 *    www.ysearch.com     6
 *    www.amazon.com      8
 *    www.nytimes.com     22
 *    www.espn.com        28
 *    www.msn.com         28
 *    www.lemonde.fr      35
 *
 * (determined in 2009-2-17 from Paris, France, results may vary depending
 *  on location)
 *
 * most high-level websites use lots of media/ad servers with different names
 * but these are generally reused when browsing through the site.
 *
 * As such, a value of 64 should be relatively comfortable at the moment.
 *
 * ******************************************
 * * NOTE - this has changed.
 * * 1) we've added IPv6 support so each dns query results in 2 responses
 * * 2) we've made this a system-wide cache, so the cost is less (it's not
 * *    duplicated in each process) and the need is greater (more processes
 * *    making different requests).
 * * Upping by 2x for IPv6
 * * Upping by another 5x for the centralized nature
 * *****************************************
 */
#define  CONFIG_MAX_ENTRIES    64 * 2 * 5

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* set to 1 to debug cache operations */
#define  DEBUG       0

/* set to 1 to debug query data */
#define  DEBUG_DATA  0

#if DEBUG
#define __DEBUG__
#else
#define __DEBUG__ __attribute__((unused))
#endif

#undef XLOG

#define XLOG(...) ({ \
    if (DEBUG) { \
        async_safe_format_log(ANDROID_LOG_DEBUG,"libc",__VA_ARGS__); \
    } else { \
        ((void)0); \
    } \
})

/** BOUNDED BUFFER FORMATTING
 **/

/* technical note:
 *
 *   the following debugging routines are used to append data to a bounded
 *   buffer they take two parameters that are:
 *
 *   - p : a pointer to the current cursor position in the buffer
 *         this value is initially set to the buffer's address.
 *
 *   - end : the address of the buffer's limit, i.e. of the first byte
 *           after the buffer. this address should never be touched.
 *
 *           IMPORTANT: it is assumed that end > buffer_address, i.e.
 *                      that the buffer is at least one byte.
 *
 *   the _bprint_() functions return the new value of 'p' after the data
 *   has been appended, and also ensure the following:
 *
 *   - the returned value will never be strictly greater than 'end'
 *
 *   - a return value equal to 'end' means that truncation occured
 *     (in which case, end[-1] will be set to 0)
 *
 *   - after returning from a _bprint_() function, the content of the buffer
 *     is always 0-terminated, even in the event of truncation.
 *
 *  these conventions allow you to call _bprint_ functions multiple times and
 *  only check for truncation at the end of the sequence, as in:
 *
 *     char  buff[1000], *p = buff, *end = p + sizeof(buff);
 *
 *     p = _bprint_c(p, end, '"');
 *     p = _bprint_s(p, end, my_string);
 *     p = _bprint_c(p, end, '"');
 *
 *     if (p >= end) {
 *        // buffer was too small
 *     }
 *
 *     printf( "%s", buff );
 */

/* add a char to a bounded buffer */
char*
_bprint_c( char*  p, char*  end, int  c )
{
    if (p < end) {
        if (p+1 == end)
            *p++ = 0;
        else {
            *p++ = (char) c;
            *p   = 0;
        }
    }
    return p;
}

/* add a sequence of bytes to a bounded buffer */
char*
_bprint_b( char*  p, char*  end, const char*  buf, int  len )
{
    int  avail = end - p;

    if (avail <= 0 || len <= 0)
        return p;

    if (avail > len)
        avail = len;

    memcpy( p, buf, avail );
    p += avail;

    if (p < end)
        p[0] = 0;
    else
        end[-1] = 0;

    return p;
}

/* add a string to a bounded buffer */
char*
_bprint_s( char*  p, char*  end, const char*  str )
{
    return _bprint_b(p, end, str, strlen(str));
}

/* add a formatted string to a bounded buffer */
char* _bprint( char*  p, char*  end, const char*  format, ... ) __DEBUG__;
char* _bprint( char*  p, char*  end, const char*  format, ... )
{
    int      avail, n;
    va_list  args;

    avail = end - p;

    if (avail <= 0)
        return p;

    va_start(args, format);
    n = vsnprintf( p, avail, format, args);
    va_end(args);

    /* certain C libraries return -1 in case of truncation */
    if (n < 0 || n > avail)
        n = avail;

    p += n;
    /* certain C libraries do not zero-terminate in case of truncation */
    if (p == end)
        p[-1] = 0;

    return p;
}

/* add a hex value to a bounded buffer, up to 8 digits */
char*
_bprint_hex( char*  p, char*  end, unsigned  value, int  numDigits )
{
    char   text[sizeof(unsigned)*2];
    int    nn = 0;

    while (numDigits-- > 0) {
        text[nn++] = "0123456789abcdef"[(value >> (numDigits*4)) & 15];
    }
    return _bprint_b(p, end, text, nn);
}

/* add the hexadecimal dump of some memory area to a bounded buffer */
char*
_bprint_hexdump( char*  p, char*  end, const uint8_t*  data, int  datalen )
{
    int   lineSize = 16;

    while (datalen > 0) {
        int  avail = datalen;
        int  nn;

        if (avail > lineSize)
            avail = lineSize;

        for (nn = 0; nn < avail; nn++) {
            if (nn > 0)
                p = _bprint_c(p, end, ' ');
            p = _bprint_hex(p, end, data[nn], 2);
        }
        for ( ; nn < lineSize; nn++ ) {
            p = _bprint_s(p, end, "   ");
        }
        p = _bprint_s(p, end, "  ");

        for (nn = 0; nn < avail; nn++) {
            int  c = data[nn];

            if (c < 32 || c > 127)
                c = '.';

            p = _bprint_c(p, end, c);
        }
        p = _bprint_c(p, end, '\n');

        data    += avail;
        datalen -= avail;
    }
    return p;
}

/* dump the content of a query of packet to the log */
void XLOG_BYTES( const void*  base, int  len ) __DEBUG__;
void XLOG_BYTES( const void*  base, int  len )
{
    if (DEBUG_DATA) {
        char  buff[1024];
        char*  p = buff, *end = p + sizeof(buff);

        p = _bprint_hexdump(p, end, base, len);
        XLOG("%s",buff);
    }
} __DEBUG__

static time_t
_time_now( void )
{
    struct timeval  tv;

    gettimeofday( &tv, NULL );
    return tv.tv_sec;
}

/* reminder: the general format of a DNS packet is the following:
 *
 *    HEADER  (12 bytes)
 *    QUESTION  (variable)
 *    ANSWER (variable)
 *    AUTHORITY (variable)
 *    ADDITIONNAL (variable)
 *
 * the HEADER is made of:
 *
 *   ID     : 16 : 16-bit unique query identification field
 *
 *   QR     :  1 : set to 0 for queries, and 1 for responses
 *   Opcode :  4 : set to 0 for queries
 *   AA     :  1 : set to 0 for queries
 *   TC     :  1 : truncation flag, will be set to 0 in queries
 *   RD     :  1 : recursion desired
 *
 *   RA     :  1 : recursion available (0 in queries)
 *   Z      :  3 : three reserved zero bits
 *   RCODE  :  4 : response code (always 0=NOERROR in queries)
 *
 *   QDCount: 16 : question count
 *   ANCount: 16 : Answer count (0 in queries)
 *   NSCount: 16: Authority Record count (0 in queries)
 *   ARCount: 16: Additionnal Record count (0 in queries)
 *
 * the QUESTION is made of QDCount Question Record (QRs)
 * the ANSWER is made of ANCount RRs
 * the AUTHORITY is made of NSCount RRs
 * the ADDITIONNAL is made of ARCount RRs
 *
 * Each Question Record (QR) is made of:
 *
 *   QNAME   : variable : Query DNS NAME
 *   TYPE    : 16       : type of query (A=1, PTR=12, MX=15, AAAA=28, ALL=255)
 *   CLASS   : 16       : class of query (IN=1)
 *
 * Each Resource Record (RR) is made of:
 *
 *   NAME    : variable : DNS NAME
 *   TYPE    : 16       : type of query (A=1, PTR=12, MX=15, AAAA=28, ALL=255)
 *   CLASS   : 16       : class of query (IN=1)
 *   TTL     : 32       : seconds to cache this RR (0=none)
 *   RDLENGTH: 16       : size of RDDATA in bytes
 *   RDDATA  : variable : RR data (depends on TYPE)
 *
 * Each QNAME contains a domain name encoded as a sequence of 'labels'
 * terminated by a zero. Each label has the following format:
 *
 *    LEN  : 8     : lenght of label (MUST be < 64)
 *    NAME : 8*LEN : label length (must exclude dots)
 *
 * A value of 0 in the encoding is interpreted as the 'root' domain and
 * terminates the encoding. So 'www.android.com' will be encoded as:
 *
 *   <3>www<7>android<3>com<0>
 *
 * Where <n> represents the byte with value 'n'
 *
 * Each NAME reflects the QNAME of the question, but has a slightly more
 * complex encoding in order to provide message compression. This is achieved
 * by using a 2-byte pointer, with format:
 *
 *    TYPE   : 2  : 0b11 to indicate a pointer, 0b01 and 0b10 are reserved
 *    OFFSET : 14 : offset to another part of the DNS packet
 *
 * The offset is relative to the start of the DNS packet and must point
 * A pointer terminates the encoding.
 *
 * The NAME can be encoded in one of the following formats:
 *
 *   - a sequence of simple labels terminated by 0 (like QNAMEs)
 *   - a single pointer
 *   - a sequence of simple labels terminated by a pointer
 *
 * A pointer shall always point to either a pointer of a sequence of
 * labels (which can themselves be terminated by either a 0 or a pointer)
 *
 * The expanded length of a given domain name should not exceed 255 bytes.
 *
 * NOTE: we don't parse the answer packets, so don't need to deal with NAME
 *       records, only QNAMEs.
 */

#define  DNS_HEADER_SIZE  12

#define  DNS_TYPE_A   "\00\01"   /* big-endian decimal 1 */
#define  DNS_TYPE_PTR "\00\014"  /* big-endian decimal 12 */
#define  DNS_TYPE_MX  "\00\017"  /* big-endian decimal 15 */
#define  DNS_TYPE_AAAA "\00\034" /* big-endian decimal 28 */
#define  DNS_TYPE_ALL "\00\0377" /* big-endian decimal 255 */

#define  DNS_CLASS_IN "\00\01"   /* big-endian decimal 1 */

typedef struct {
    const uint8_t*  base;
    const uint8_t*  end;
    const uint8_t*  cursor;
} DnsPacket;

static void
_dnsPacket_init( DnsPacket*  packet, const uint8_t*  buff, int  bufflen )
{
    packet->base   = buff;
    packet->end    = buff + bufflen;
    packet->cursor = buff;
}

static void
_dnsPacket_rewind( DnsPacket*  packet )
{
    packet->cursor = packet->base;
}

static void
_dnsPacket_skip( DnsPacket*  packet, int  count )
{
    const uint8_t*  p = packet->cursor + count;

    if (p > packet->end)
        p = packet->end;

    packet->cursor = p;
}

static int
_dnsPacket_readInt16( DnsPacket*  packet )
{
    const uint8_t*  p = packet->cursor;

    if (p+2 > packet->end)
        return -1;

    packet->cursor = p+2;
    return (p[0]<< 8) | p[1];
}

/** QUERY CHECKING
 **/

/* check bytes in a dns packet. returns 1 on success, 0 on failure.
 * the cursor is only advanced in the case of success
 */
static int
_dnsPacket_checkBytes( DnsPacket*  packet, int  numBytes, const void*  bytes )
{
    const uint8_t*  p = packet->cursor;

    if (p + numBytes > packet->end)
        return 0;

    if (memcmp(p, bytes, numBytes) != 0)
        return 0;

    packet->cursor = p + numBytes;
    return 1;
}

/* parse and skip a given QNAME stored in a query packet,
 * from the current cursor position. returns 1 on success,
 * or 0 for malformed data.
 */
static int
_dnsPacket_checkQName( DnsPacket*  packet )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    for (;;) {
        int  c;

        if (p >= end)
            break;

        c = *p++;

        if (c == 0) {
            packet->cursor = p;
            return 1;
        }

        /* we don't expect label compression in QNAMEs */
        if (c >= 64)
            break;

        p += c;
        /* we rely on the bound check at the start
         * of the loop here */
    }
    /* malformed data */
    XLOG("malformed QNAME");
    return 0;
}

/* parse and skip a given QR stored in a packet.
 * returns 1 on success, and 0 on failure
 */
static int
_dnsPacket_checkQR( DnsPacket*  packet )
{
    if (!_dnsPacket_checkQName(packet))
        return 0;

    /* TYPE must be one of the things we support */
    if (!_dnsPacket_checkBytes(packet, 2, DNS_TYPE_A) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_PTR) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_MX) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_AAAA) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_ALL))
    {
        XLOG("unsupported TYPE");
        return 0;
    }
    /* CLASS must be IN */
    if (!_dnsPacket_checkBytes(packet, 2, DNS_CLASS_IN)) {
        XLOG("unsupported CLASS");
        return 0;
    }

    return 1;
}

/* check the header of a DNS Query packet, return 1 if it is one
 * type of query we can cache, or 0 otherwise
 */
static int
_dnsPacket_checkQuery( DnsPacket*  packet )
{
    const uint8_t*  p = packet->base;
    int             qdCount, anCount, dnCount, arCount;

    if (p + DNS_HEADER_SIZE > packet->end) {
        XLOG("query packet too small");
        return 0;
    }

    /* QR must be set to 0, opcode must be 0 and AA must be 0 */
    /* RA, Z, and RCODE must be 0 */
    if ((p[2] & 0xFC) != 0 || (p[3] & 0xCF) != 0) {
        XLOG("query packet flags unsupported");
        return 0;
    }

    /* Note that we ignore the TC, RD, CD, and AD bits here for the
     * following reasons:
     *
     * - there is no point for a query packet sent to a server
     *   to have the TC bit set, but the implementation might
     *   set the bit in the query buffer for its own needs
     *   between a _resolv_cache_lookup and a
     *   _resolv_cache_add. We should not freak out if this
     *   is the case.
     *
     * - we consider that the result from a query might depend on
     *   the RD, AD, and CD bits, so these bits
     *   should be used to differentiate cached result.
     *
     *   this implies that these bits are checked when hashing or
     *   comparing query packets, but not TC
     */

    /* ANCOUNT, DNCOUNT and ARCOUNT must be 0 */
    qdCount = (p[4] << 8) | p[5];
    anCount = (p[6] << 8) | p[7];
    dnCount = (p[8] << 8) | p[9];
    arCount = (p[10]<< 8) | p[11];

    if (anCount != 0 || dnCount != 0 || arCount > 1) {
        XLOG("query packet contains non-query records");
        return 0;
    }

    if (qdCount == 0) {
        XLOG("query packet doesn't contain query record");
        return 0;
    }

    /* Check QDCOUNT QRs */
    packet->cursor = p + DNS_HEADER_SIZE;

    for (;qdCount > 0; qdCount--)
        if (!_dnsPacket_checkQR(packet))
            return 0;

    return 1;
}

/** QUERY DEBUGGING
 **/
#if DEBUG
static char*
_dnsPacket_bprintQName(DnsPacket*  packet, char*  bp, char*  bend)
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;
    int             first = 1;

    for (;;) {
        int  c;

        if (p >= end)
            break;

        c = *p++;

        if (c == 0) {
            packet->cursor = p;
            return bp;
        }

        /* we don't expect label compression in QNAMEs */
        if (c >= 64)
            break;

        if (first)
            first = 0;
        else
            bp = _bprint_c(bp, bend, '.');

        bp = _bprint_b(bp, bend, (const char*)p, c);

        p += c;
        /* we rely on the bound check at the start
         * of the loop here */
    }
    /* malformed data */
    bp = _bprint_s(bp, bend, "<MALFORMED>");
    return bp;
}

static char*
_dnsPacket_bprintQR(DnsPacket*  packet, char*  p, char*  end)
{
#define  QQ(x)   { DNS_TYPE_##x, #x }
    static const struct {
        const char*  typeBytes;
        const char*  typeString;
    } qTypes[] =
    {
        QQ(A), QQ(PTR), QQ(MX), QQ(AAAA), QQ(ALL),
        { NULL, NULL }
    };
    int          nn;
    const char*  typeString = NULL;

    /* dump QNAME */
    p = _dnsPacket_bprintQName(packet, p, end);

    /* dump TYPE */
    p = _bprint_s(p, end, " (");

    for (nn = 0; qTypes[nn].typeBytes != NULL; nn++) {
        if (_dnsPacket_checkBytes(packet, 2, qTypes[nn].typeBytes)) {
            typeString = qTypes[nn].typeString;
            break;
        }
    }

    if (typeString != NULL)
        p = _bprint_s(p, end, typeString);
    else {
        int  typeCode = _dnsPacket_readInt16(packet);
        p = _bprint(p, end, "UNKNOWN-%d", typeCode);
    }

    p = _bprint_c(p, end, ')');

    /* skip CLASS */
    _dnsPacket_skip(packet, 2);
    return p;
}

/* this function assumes the packet has already been checked */
static char*
_dnsPacket_bprintQuery( DnsPacket*  packet, char*  p, char*  end )
{
    int   qdCount;

    if (packet->base[2] & 0x1) {
        p = _bprint_s(p, end, "RECURSIVE ");
    }

    _dnsPacket_skip(packet, 4);
    qdCount = _dnsPacket_readInt16(packet);
    _dnsPacket_skip(packet, 6);

    for ( ; qdCount > 0; qdCount-- ) {
        p = _dnsPacket_bprintQR(packet, p, end);
    }
    return p;
}
#endif


/** QUERY HASHING SUPPORT
 **
 ** THE FOLLOWING CODE ASSUMES THAT THE INPUT PACKET HAS ALREADY
 ** BEEN SUCCESFULLY CHECKED.
 **/

/* use 32-bit FNV hash function */
#define  FNV_MULT   16777619U
#define  FNV_BASIS  2166136261U

static unsigned
_dnsPacket_hashBytes( DnsPacket*  packet, int  numBytes, unsigned  hash )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    while (numBytes > 0 && p < end) {
        hash = hash*FNV_MULT ^ *p++;
    }
    packet->cursor = p;
    return hash;
}


static unsigned
_dnsPacket_hashQName( DnsPacket*  packet, unsigned  hash )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    for (;;) {
        int  c;

        if (p >= end) {  /* should not happen */
            XLOG("%s: INTERNAL_ERROR: read-overflow !!\n", __FUNCTION__);
            break;
        }

        c = *p++;

        if (c == 0)
            break;

        if (c >= 64) {
            XLOG("%s: INTERNAL_ERROR: malformed domain !!\n", __FUNCTION__);
            break;
        }
        if (p + c >= end) {
            XLOG("%s: INTERNAL_ERROR: simple label read-overflow !!\n",
                    __FUNCTION__);
            break;
        }
        while (c > 0) {
            hash = hash*FNV_MULT ^ *p++;
            c   -= 1;
        }
    }
    packet->cursor = p;
    return hash;
}

static unsigned
_dnsPacket_hashQR( DnsPacket*  packet, unsigned  hash )
{
    hash = _dnsPacket_hashQName(packet, hash);
    hash = _dnsPacket_hashBytes(packet, 4, hash); /* TYPE and CLASS */
    return hash;
}

static unsigned
_dnsPacket_hashRR( DnsPacket*  packet, unsigned  hash )
{
    int rdlength;
    hash = _dnsPacket_hashQR(packet, hash);
    hash = _dnsPacket_hashBytes(packet, 4, hash); /* TTL */
    rdlength = _dnsPacket_readInt16(packet);
    hash = _dnsPacket_hashBytes(packet, rdlength, hash); /* RDATA */
    return hash;
}

static unsigned
_dnsPacket_hashQuery( DnsPacket*  packet )
{
    unsigned  hash = FNV_BASIS;
    int       count, arcount;
    _dnsPacket_rewind(packet);

    /* ignore the ID */
    _dnsPacket_skip(packet, 2);

    /* we ignore the TC bit for reasons explained in
     * _dnsPacket_checkQuery().
     *
     * however we hash the RD bit to differentiate
     * between answers for recursive and non-recursive
     * queries.
     */
    hash = hash*FNV_MULT ^ (packet->base[2] & 1);

    /* mark the first header byte as processed */
    _dnsPacket_skip(packet, 1);

    /* process the second header byte */
    hash = _dnsPacket_hashBytes(packet, 1, hash);

    /* read QDCOUNT */
    count = _dnsPacket_readInt16(packet);

    /* assume: ANcount and NScount are 0 */
    _dnsPacket_skip(packet, 4);

    /* read ARCOUNT */
    arcount = _dnsPacket_readInt16(packet);

    /* hash QDCOUNT QRs */
    for ( ; count > 0; count-- )
        hash = _dnsPacket_hashQR(packet, hash);

    /* hash ARCOUNT RRs */
    for ( ; arcount > 0; arcount-- )
        hash = _dnsPacket_hashRR(packet, hash);

    return hash;
}


/** QUERY COMPARISON
 **
 ** THE FOLLOWING CODE ASSUMES THAT THE INPUT PACKETS HAVE ALREADY
 ** BEEN SUCCESFULLY CHECKED.
 **/

static int
_dnsPacket_isEqualDomainName( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    const uint8_t*  p1   = pack1->cursor;
    const uint8_t*  end1 = pack1->end;
    const uint8_t*  p2   = pack2->cursor;
    const uint8_t*  end2 = pack2->end;

    for (;;) {
        int  c1, c2;

        if (p1 >= end1 || p2 >= end2) {
            XLOG("%s: INTERNAL_ERROR: read-overflow !!\n", __FUNCTION__);
            break;
        }
        c1 = *p1++;
        c2 = *p2++;
        if (c1 != c2)
            break;

        if (c1 == 0) {
            pack1->cursor = p1;
            pack2->cursor = p2;
            return 1;
        }
        if (c1 >= 64) {
            XLOG("%s: INTERNAL_ERROR: malformed domain !!\n", __FUNCTION__);
            break;
        }
        if ((p1+c1 > end1) || (p2+c1 > end2)) {
            XLOG("%s: INTERNAL_ERROR: simple label read-overflow !!\n",
                    __FUNCTION__);
            break;
        }
        if (memcmp(p1, p2, c1) != 0)
            break;
        p1 += c1;
        p2 += c1;
        /* we rely on the bound checks at the start of the loop */
    }
    /* not the same, or one is malformed */
    XLOG("different DN");
    return 0;
}

static int
_dnsPacket_isEqualBytes( DnsPacket*  pack1, DnsPacket*  pack2, int  numBytes )
{
    const uint8_t*  p1 = pack1->cursor;
    const uint8_t*  p2 = pack2->cursor;

    if ( p1 + numBytes > pack1->end || p2 + numBytes > pack2->end )
        return 0;

    if ( memcmp(p1, p2, numBytes) != 0 )
        return 0;

    pack1->cursor += numBytes;
    pack2->cursor += numBytes;
    return 1;
}

static int
_dnsPacket_isEqualQR( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    /* compare domain name encoding + TYPE + CLASS */
    if ( !_dnsPacket_isEqualDomainName(pack1, pack2) ||
         !_dnsPacket_isEqualBytes(pack1, pack2, 2+2) )
        return 0;

    return 1;
}

static int
_dnsPacket_isEqualRR( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    int rdlength1, rdlength2;
    /* compare query + TTL */
    if ( !_dnsPacket_isEqualQR(pack1, pack2) ||
         !_dnsPacket_isEqualBytes(pack1, pack2, 4) )
        return 0;

    /* compare RDATA */
    rdlength1 = _dnsPacket_readInt16(pack1);
    rdlength2 = _dnsPacket_readInt16(pack2);
    if ( rdlength1 != rdlength2 ||
         !_dnsPacket_isEqualBytes(pack1, pack2, rdlength1) )
        return 0;

    return 1;
}

static int
_dnsPacket_isEqualQuery( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    int  count1, count2, arcount1, arcount2;

    /* compare the headers, ignore most fields */
    _dnsPacket_rewind(pack1);
    _dnsPacket_rewind(pack2);

    /* compare RD, ignore TC, see comment in _dnsPacket_checkQuery */
    if ((pack1->base[2] & 1) != (pack2->base[2] & 1)) {
        XLOG("different RD");
        return 0;
    }

    if (pack1->base[3] != pack2->base[3]) {
        XLOG("different CD or AD");
        return 0;
    }

    /* mark ID and header bytes as compared */
    _dnsPacket_skip(pack1, 4);
    _dnsPacket_skip(pack2, 4);

    /* compare QDCOUNT */
    count1 = _dnsPacket_readInt16(pack1);
    count2 = _dnsPacket_readInt16(pack2);
    if (count1 != count2 || count1 < 0) {
        XLOG("different QDCOUNT");
        return 0;
    }

    /* assume: ANcount and NScount are 0 */
    _dnsPacket_skip(pack1, 4);
    _dnsPacket_skip(pack2, 4);

    /* compare ARCOUNT */
    arcount1 = _dnsPacket_readInt16(pack1);
    arcount2 = _dnsPacket_readInt16(pack2);
    if (arcount1 != arcount2 || arcount1 < 0) {
        XLOG("different ARCOUNT");
        return 0;
    }

    /* compare the QDCOUNT QRs */
    for ( ; count1 > 0; count1-- ) {
        if (!_dnsPacket_isEqualQR(pack1, pack2)) {
            XLOG("different QR");
            return 0;
        }
    }

    /* compare the ARCOUNT RRs */
    for ( ; arcount1 > 0; arcount1-- ) {
        if (!_dnsPacket_isEqualRR(pack1, pack2)) {
            XLOG("different additional RR");
            return 0;
        }
    }
    return 1;
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* cache entry. for simplicity, 'hash' and 'hlink' are inlined in this
 * structure though they are conceptually part of the hash table.
 *
 * similarly, mru_next and mru_prev are part of the global MRU list
 */
typedef struct Entry {
    unsigned int     hash;   /* hash value */
    struct Entry*    hlink;  /* next in collision chain */
    struct Entry*    mru_prev;
    struct Entry*    mru_next;

    const uint8_t*   query;
    int              querylen;
    const uint8_t*   answer;
    int              answerlen;
    time_t           expires;   /* time_t when the entry isn't valid any more */
    int              id;        /* for debugging purpose */
} Entry;

/**
 * Find the TTL for a negative DNS result.  This is defined as the minimum
 * of the SOA records TTL and the MINIMUM-TTL field (RFC-2308).
 *
 * Return 0 if not found.
 */
static u_long
answer_getNegativeTTL(ns_msg handle) {
    int n, nscount;
    u_long result = 0;
    ns_rr rr;

    nscount = ns_msg_count(handle, ns_s_ns);
    for (n = 0; n < nscount; n++) {
        if ((ns_parserr(&handle, ns_s_ns, n, &rr) == 0) && (ns_rr_type(rr) == ns_t_soa)) {
            const u_char *rdata = ns_rr_rdata(rr); // find the data
            const u_char *edata = rdata + ns_rr_rdlen(rr); // add the len to find the end
            int len;
            u_long ttl, rec_result = ns_rr_ttl(rr);

            // find the MINIMUM-TTL field from the blob of binary data for this record
            // skip the server name
            len = dn_skipname(rdata, edata);
            if (len == -1) continue; // error skipping
            rdata += len;

            // skip the admin name
            len = dn_skipname(rdata, edata);
            if (len == -1) continue; // error skipping
            rdata += len;

            if (edata - rdata != 5*NS_INT32SZ) continue;
            // skip: serial number + refresh interval + retry interval + expiry
            rdata += NS_INT32SZ * 4;
            // finally read the MINIMUM TTL
            ttl = ns_get32(rdata);
            if (ttl < rec_result) {
                rec_result = ttl;
            }
            // Now that the record is read successfully, apply the new min TTL
            if (n == 0 || rec_result < result) {
                result = rec_result;
            }
        }
    }
    return result;
}

/**
 * Parse the answer records and find the appropriate
 * smallest TTL among the records.  This might be from
 * the answer records if found or from the SOA record
 * if it's a negative result.
 *
 * The returned TTL is the number of seconds to
 * keep the answer in the cache.
 *
 * In case of parse error zero (0) is returned which
 * indicates that the answer shall not be cached.
 */
static u_long
answer_getTTL(const void* answer, int answerlen)
{
    ns_msg handle;
    int ancount, n;
    u_long result, ttl;
    ns_rr rr;

    result = 0;
    if (ns_initparse(answer, answerlen, &handle) >= 0) {
        // get number of answer records
        ancount = ns_msg_count(handle, ns_s_an);

        if (ancount == 0) {
            // a response with no answers?  Cache this negative result.
            result = answer_getNegativeTTL(handle);
        } else {
            for (n = 0; n < ancount; n++) {
                if (ns_parserr(&handle, ns_s_an, n, &rr) == 0) {
                    ttl = ns_rr_ttl(rr);
                    if (n == 0 || ttl < result) {
                        result = ttl;
                    }
                } else {
                    XLOG("ns_parserr failed ancount no = %d. errno = %s\n", n, strerror(errno));
                }
            }
        }
    } else {
        XLOG("ns_parserr failed. %s\n", strerror(errno));
    }

    XLOG("TTL = %lu\n", result);

    return result;
}

static void
e
```