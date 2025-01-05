Response:
The user wants a summary of the functionality of the provided C code snippet from `bionic/libc/dns/resolv/res_cache.c`. This is part 2 of a 3-part series, so I should focus on summarizing the functionality present in this specific chunk of code.

Here's a breakdown of the code's main responsibilities:

1. **Cache Entry Management:** Functions to allocate, free, initialize, compare, add, and remove cache entries. This includes managing a Most Recently Used (MRU) list for efficient eviction.
2. **Hash Table Implementation:** The code uses a hash table with external chaining for storing cache entries. Functions are provided to calculate the hash of an entry and to look up entries in the hash table.
3. **Pending Request Handling:** Mechanisms to track and manage pending DNS requests to avoid redundant queries. This involves a linked list of pending requests and the use of condition variables for synchronization.
4. **Cache-Level Operations:** Functions to flush the entire cache, remove expired entries, and remove the oldest entry.
5. **Network-Specific Cache Management:**  The code supports managing separate DNS caches for different network interfaces (identified by `netid`). It includes functions to create, find, and delete these network-specific caches.
6. **Nameserver Management:** Functions to set and retrieve nameservers associated with a network cache. It also includes logic to check if the nameserver list has changed.
7. **Statistics Management:** Basic framework for tracking statistics related to nameserver usage, though the actual implementation for adding and clearing statistics is in the last part of the code.

Therefore, the summary should focus on these key aspects.
这段代码主要负责以下功能：

1. **缓存条目的管理:**
   - `entry_free`: 释放缓存条目 `Entry` 占用的内存。
   - `entry_mru_remove`: 从最近使用 (MRU) 列表中移除一个缓存条目。
   - `entry_mru_add`: 将一个缓存条目添加到 MRU 列表的头部。
   - `entry_hash`: 计算缓存条目的哈希值，用于在哈希表中定位。
   - `entry_init_key`: 初始化一个用于查找的缓存条目，同时检查查询数据包的有效性。
   - `entry_alloc`: 分配一个新的缓存条目，并将查询和应答数据复制到其中。
   - `entry_equals`: 比较两个缓存条目是否相等（基于查询内容）。

2. **缓存的查找、添加和删除:**
   - `_cache_lookup_p`: 在哈希表中查找与给定键匹配的缓存条目。返回指向条目指针的指针，方便后续添加或删除操作。
   - `_cache_add_p`: 将新的缓存条目添加到哈希表和 MRU 列表中。
   - `_cache_remove_p`: 从哈希表和 MRU 列表中移除一个缓存条目。
   - `_cache_remove_oldest`: 从缓存中移除最老的条目（MRU 列表的尾部），用于在缓存满时腾出空间。
   - `_cache_remove_expired`: 遍历缓存，移除所有过期的条目。

3. **处理挂起的 DNS 请求:**
   - 代码中定义了 `pending_req_info` 结构体，用于记录正在处理的 DNS 请求的哈希值和条件变量。
   - `_cache_check_pending_request_locked`: 检查是否已经有相同的请求正在处理。如果是，当前线程会等待之前的请求完成。
   - `_cache_notify_waiting_tid_locked`: 当一个请求成功添加到缓存后，通知等待该请求的线程。
   - `_resolv_cache_query_failed`: 当一个 DNS 查询失败时，通知等待该查询的线程。
   - `_cache_flush_pending_requests_locked`: 清空所有挂起的请求，并唤醒等待的线程。

4. **缓存的初始化和管理:**
   - 定义了 `Cache` 结构体，表示一个 DNS 缓存，包含哈希表、MRU 列表、最大条目数等信息。
   - `_resolv_cache_create`: 创建一个新的 DNS 缓存结构。
   - `_cache_flush_locked`: 清空一个指定的缓存，包括所有条目和挂起的请求。
   - `_res_cache_get_max_entries`: 获取缓存的最大条目数，受环境变量 "ANDROID_DNS_MODE" 影响。

5. **网络相关的缓存管理:**
   - 定义了 `resolv_cache_info` 结构体，用于关联一个网络 ID (`netid`) 和一个 `Cache` 结构体，以及该网络相关的 nameserver 信息。
   - `_find_named_cache_locked`: 根据网络 ID 查找对应的缓存。
   - `_get_res_cache_for_net_locked`: 根据网络 ID 获取或创建一个缓存。
   - `_flush_cache_for_net_locked`: 清空指定网络 ID 的缓存。
   - `_resolv_delete_cache_for_net`: 删除指定网络 ID 的缓存。
   - `_create_cache_info`: 创建一个新的 `resolv_cache_info` 结构体。
   - `_insert_cache_info_locked`: 将 `resolv_cache_info` 结构体插入到链表中。
   - `_find_cache_info_locked`: 根据网络 ID 查找对应的 `resolv_cache_info` 结构体。

6. **Nameserver 的设置和管理:**
   - `_resolv_set_nameservers_for_net`: 为指定网络 ID 的缓存设置 nameserver 列表和搜索域。
   - `_resolv_is_nameservers_equal_locked`: 比较新的 nameserver 列表是否与当前缓存的 nameserver 列表相同。
   - `_free_nameservers_locked`: 释放缓存中存储的 nameserver 信息。
   - `_resolv_populate_res_for_net`: 将指定网络 ID 的 nameserver 信息填充到 `res_state` 结构体中，供 DNS 解析器使用。

7. **缓存的查找和添加操作的封装:**
   - `_resolv_cache_lookup`: 在缓存中查找指定的 DNS 查询。如果找到且未过期，则返回缓存的应答。
   - `_resolv_cache_add`: 将 DNS 查询及其应答添加到缓存中。

**与 Android 功能的关系举例:**

- **网络切换:** 当 Android 设备连接到新的 Wi-Fi 网络或移动数据网络时，`_resolv_set_nameservers_for_net` 会被调用，使用新的网络提供的 DNS 服务器信息更新对应 `netid` 的缓存信息。
- **应用发起 DNS 查询:** 当 Android 应用程序需要解析域名时，libc 的 DNS 解析函数会首先调用 `_resolv_cache_lookup` 来检查缓存中是否已存在该查询的记录。如果存在，则直接返回缓存的结果，避免重复的 DNS 查询，提高效率并节省电量。
- **DNS 缓存过期:** 缓存中的 DNS 记录都有过期时间 (TTL)。当 `_resolv_cache_lookup` 发现缓存的记录已过期时，会将其移除，并会发起新的 DNS 查询。
- **后台 DNS 解析:**  Android 系统的一些后台服务可能也会进行 DNS 查询，这些查询也会受到 DNS 缓存的影响。

**libc 函数的实现解释:**

- **`free(e)`:**  `entry_free` 函数直接调用 `free` 来释放 `Entry` 结构体所占用的内存。 由于 `Entry` 结构体以及其内部的 `query` 和 `answer` 数据都分配在同一块内存中，所以只需要释放 `Entry` 结构体的起始地址即可释放所有相关内存。
- **`memset(e, 0, sizeof(*e))`:**  `entry_init_key` 使用 `memset` 将 `Entry` 结构体的内存初始化为零。这是一种常见的做法，可以确保结构体中的所有字段都处于已知的初始状态。
- **`calloc(size, 1)`:** `entry_alloc` 使用 `calloc` 来分配一块大小为 `sizeof(*e) + init->querylen + answerlen` 的内存。`calloc` 会将分配的内存初始化为零，这对于缓存条目来说是一个好的做法，因为可以避免读取到未初始化的数据。分配的内存块会依次存放 `Entry` 结构体本身，然后是查询数据，最后是应答数据。
- **`memcpy((char*)e->query, init->query, e->querylen)` 和 `memcpy((char*)e->answer, answer, e->answerlen)`:** `entry_alloc` 使用 `memcpy` 将查询数据和应答数据从传入的参数复制到新分配的缓存条目的内存中。
- **`pthread_once(&_res_cache_once, _res_cache_init)`:** 这是一个 POSIX 线程同步机制，确保 `_res_cache_init` 函数只在第一次调用 `pthread_once` 时执行，用于初始化全局的缓存列表锁。
- **`pthread_mutex_lock(&_res_cache_list_lock)` 和 `pthread_mutex_unlock(&_res_cache_list_lock)`:** 这是一对 POSIX 线程同步机制，用于保护对全局缓存列表的并发访问，确保多线程环境下的数据一致性。在访问或修改全局缓存列表之前需要获取锁，操作完成后释放锁。
- **`pthread_cond_init(&ri->cond, NULL)` 和 `pthread_cond_destroy(&ri->cond)`:** 用于初始化和销毁条件变量。条件变量用于线程间的同步，允许线程在特定条件下挂起并等待其他线程的通知。
- **`pthread_cond_broadcast(&tmp->cond)`:** 唤醒所有等待在指定条件变量上的线程。
- **`pthread_cond_timedwait(&ri->cond, &_res_cache_list_lock, &ts)`:** 使当前线程等待在指定的条件变量上，直到接收到广播信号或超时。在等待期间会释放互斥锁，并在被唤醒后重新获取锁。
- **`strdup(servers[i])`:** `_resolv_set_nameservers_for_net` 使用 `strdup` 复制 nameserver 字符串。`strdup` 会分配新的内存来存储复制的字符串。
- **`getaddrinfo(servers[i], sbuf, &hints, &nsaddrinfo[i])`:** `_resolv_set_nameservers_for_net` 使用 `getaddrinfo` 函数将 nameserver 的字符串表示转换为网络地址结构 `addrinfo`。这允许代码处理 IPv4 和 IPv6 地址。
- **`strlcpy(cache_info->defdname, domains, sizeof(cache_info->defdname))`:** `_resolv_set_nameservers_for_net` 使用 `strlcpy` 安全地将域名搜索路径复制到缓存信息结构体中，防止缓冲区溢出。
- **`strchr(cache_info->defdname, '\n')`:** `_resolv_set_nameservers_for_net` 使用 `strchr` 查找换行符，并将其替换为 null 终止符，以处理域名搜索路径中的换行。

**涉及 dynamic linker 的功能:**

这段代码本身不直接涉及 dynamic linker 的功能。它主要关注 DNS 缓存的逻辑实现。Dynamic linker 负责在程序运行时加载共享库，并将程序中的符号引用解析到共享库中的实现。

虽然这段代码没有直接的 dynamic linker 调用，但它是 `libc.so` 的一部分，而 `libc.so` 本身是由 dynamic linker 加载的。当应用程序调用诸如 `getaddrinfo` 这样的 libc 函数时，dynamic linker 确保 `libc.so` 已经被加载，并且函数调用能够正确地链接到 `libc.so` 中对应的实现。

**so 布局样本:**

`libc.so` 的布局非常复杂，包含大量的函数和数据。以下是一个简化的布局示例，展示了 `res_cache.c` 中部分函数可能存在的位置：

```
libc.so:
    ...
    .text:  // 代码段
        entry_free:
            ...
        entry_mru_remove:
            ...
        entry_mru_add:
            ...
        entry_hash:
            ...
        entry_init_key:
            ...
        entry_alloc:
            ...
        entry_equals:
            ...
        _cache_lookup_p:
            ...
        _cache_add_p:
            ...
        _cache_remove_p:
            ...
        _cache_remove_oldest:
            ...
        _cache_remove_expired:
            ...
        _resolv_cache_lookup:
            ...
        _resolv_cache_add:
            ...
        _res_cache_init:
            ...
        _get_res_cache_for_net_locked:
            ...
        _flush_cache_for_net_locked:
            ...
        _resolv_set_nameservers_for_net:
            ...
        _resolv_populate_res_for_net:
            ...
        ...
    .data:  // 数据段
        _res_cache_list:  // 全局的缓存信息链表头
            ...
        _res_cache_list_lock: // 保护缓存列表的互斥锁
            ...
        _res_cache_once: // 用于 _res_cache_init 的 once 控制变量
            ...
        ...
    .bss:   // 未初始化数据段
        ...
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译链接依赖 `libc.so` 的程序时，链接器会记录程序中对 `libc.so` 中函数的引用（例如 `free`, `calloc`, `memcpy`, `pthread_mutex_lock` 等）。
2. **运行时链接:** 当程序启动时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库 `libc.so` 到内存中。
3. **符号解析:** dynamic linker 会遍历程序中的符号引用表（GOT - Global Offset Table）和延迟绑定表（PLT - Procedure Linkage Table），将程序中对 `libc.so` 中函数的调用地址解析为 `libc.so` 在内存中的实际函数地址。例如，当程序调用 `free` 时，实际上会跳转到 PLT 中的一个桩代码，该桩代码会调用 dynamic linker 来解析 `free` 的地址，并将解析结果写入 GOT，然后跳转到 `libc.so` 中 `free` 函数的实际地址。后续对 `free` 的调用将直接通过 GOT 跳转，避免重复解析。

**假设输入与输出（逻辑推理）：**

假设我们调用 `_resolv_cache_lookup` 函数：

**假设输入:**

- `netid`: 101 (表示一个特定的网络)
- `query`: 指向一个 DNS 查询数据包的指针 (例如，查询 "www.google.com" 的 A 记录)
- `querylen`: 查询数据包的长度
- `answer`: 指向一个用于接收 DNS 应答的缓冲区指针
- `answersize`: 应答缓冲区的长度

**可能输出:**

- **情况 1 (缓存命中且未过期):**
    - 函数返回 `RESOLV_CACHE_FOUND`。
    - `answer` 缓冲区中包含 "www.google.com" 的 IP 地址。
    - `answerlen` 指向的整数被设置为应答的实际长度。
- **情况 2 (缓存未命中):**
    - 函数返回 `RESOLV_CACHE_NOTFOUND`。
    - `answer` 缓冲区内容不变（或部分被修改，取决于实现细节）。
    - `answerlen` 指向的整数可能为 0 或保持初始值。
- **情况 3 (缓存命中但已过期):**
    - 函数返回 `RESOLV_CACHE_NOTFOUND`。
    - 缓存中对应的过期条目会被移除。
- **情况 4 (应答数据过长):**
    - 函数返回 `RESOLV_CACHE_UNSUPPORTED`。
    - `answer` 缓冲区内容不变。

**用户或编程常见的使用错误:**

- **在多线程环境下不加锁访问缓存:**  由于 DNS 缓存是全局共享的，多个线程同时访问和修改缓存可能导致数据竞争和不一致。正确的做法是使用互斥锁（如代码中的 `_res_cache_list_lock`）来保护对缓存的访问。
- **错误地计算缓存大小或缓冲区大小:** 在调用 `_resolv_cache_lookup` 时，如果 `answersize` 参数传递的值小于实际的应答大小，会导致应答数据被截断或程序崩溃。
- **忘记初始化 `answerlen` 指针指向的整数:** 在调用 `_resolv_cache_lookup` 之前，应该确保 `answerlen` 指针指向一个有效的整数变量。
- **在高并发场景下频繁地刷新缓存:**  频繁地调用 `_resolv_flush_cache_for_net` 会导致缓存失效，增加 DNS 查询的次数，降低性能。

**Android Framework 或 NDK 如何到达这里:**

1. **应用程序发起网络请求:**  Android 应用程序通常使用 Java 网络 API (例如 `java.net.URL`, `java.net.HttpURLConnection`) 或 NDK 中的网络函数（例如 sockets 相关函数）发起网络请求。
2. **Java 网络 API 调用到 Native 代码:** 当使用 Java 网络 API 时，相关的调用最终会通过 JNI (Java Native Interface) 桥接到 Android Runtime (ART) 中的 native 代码。
3. **Native 代码调用 libc 的 DNS 解析函数:** ART 或 Android 系统库的 native 代码会调用 `libc.so` 提供的 DNS 解析函数，例如 `getaddrinfo`。
4. **`getaddrinfo` 内部使用 DNS 缓存:** `getaddrinfo` 函数内部会调用与 DNS 缓存相关的函数，例如 `_resolv_cache_lookup`，来检查缓存中是否存在对应的 DNS 记录。
5. **缓存操作:** 如果缓存命中且未过期，则直接返回缓存的结果。否则，会发起实际的 DNS 查询，并将结果添加到缓存中（通过 `_resolv_cache_add`）。

**Frida Hook 示例:**

可以使用 Frida Hook 来观察 `_resolv_cache_lookup` 函数的调用和参数：

```javascript
if (Process.platform === 'android') {
  const resolv_cache_lookup = Module.findExportByName("libc.so", "_resolv_cache_lookup");
  if (resolv_cache_lookup) {
    Interceptor.attach(resolv_cache_lookup, {
      onEnter: function (args) {
        const netid = args[0].toInt();
        const queryPtr = args[1];
        const querylen = args[2].toInt();
        const answerPtr = args[3];
        const answersize = args[4].toInt();
        const answerlenPtr = args[5];

        const queryData = Memory.readByteArray(queryPtr, querylen);
        console.log("Hooking _resolv_cache_lookup");
        console.log("  netid:", netid);
        console.log("  query (hex):", hexdump(queryData));
        console.log("  querylen:", querylen);
        console.log("  answersize:", answersize);
        console.log("  answerlenPtr:", answerlenPtr);
      },
      onLeave: function (retval) {
        console.log("  Return value:", retval);
        // 可以进一步读取 answer 缓冲区的内容
      }
    });
  } else {
    console.log("Failed to find _resolv_cache_lookup");
  }
}
```

这个 Frida 脚本会 hook `_resolv_cache_lookup` 函数，并在函数调用时打印出 `netid`、查询数据包内容、查询长度、应答缓冲区大小等信息，以及函数的返回值。你可以根据需要修改脚本来查看应答缓冲区的内容。

Prompt: 
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
这是第2部分，共3部分，请归纳一下它的功能

"""
ntry_free( Entry*  e )
{
    /* everything is allocated in a single memory block */
    if (e) {
        free(e);
    }
}

static __inline__ void entry_mru_remove(Entry* e) {
  e->mru_prev->mru_next = e->mru_next;
  e->mru_next->mru_prev = e->mru_prev;
}

static __inline__ void entry_mru_add(Entry* e, Entry* list) {
  Entry* first = list->mru_next;

  e->mru_next = first;
  e->mru_prev = list;

  list->mru_next = e;
  first->mru_prev = e;
}

/* compute the hash of a given entry, this is a hash of most
 * data in the query (key) */
static unsigned
entry_hash( const Entry*  e )
{
    DnsPacket  pack[1];

    _dnsPacket_init(pack, e->query, e->querylen);
    return _dnsPacket_hashQuery(pack);
}

/* initialize an Entry as a search key, this also checks the input query packet
 * returns 1 on success, or 0 in case of unsupported/malformed data */
static int
entry_init_key( Entry*  e, const void*  query, int  querylen )
{
    DnsPacket  pack[1];

    memset(e, 0, sizeof(*e));

    e->query    = query;
    e->querylen = querylen;
    e->hash     = entry_hash(e);

    _dnsPacket_init(pack, query, querylen);

    return _dnsPacket_checkQuery(pack);
}

/* allocate a new entry as a cache node */
static Entry*
entry_alloc( const Entry*  init, const void*  answer, int  answerlen )
{
    Entry*  e;
    int     size;

    size = sizeof(*e) + init->querylen + answerlen;
    e    = calloc(size, 1);
    if (e == NULL)
        return e;

    e->hash     = init->hash;
    e->query    = (const uint8_t*)(e+1);
    e->querylen = init->querylen;

    memcpy( (char*)e->query, init->query, e->querylen );

    e->answer    = e->query + e->querylen;
    e->answerlen = answerlen;

    memcpy( (char*)e->answer, answer, e->answerlen );

    return e;
}

static int
entry_equals( const Entry*  e1, const Entry*  e2 )
{
    DnsPacket  pack1[1], pack2[1];

    if (e1->querylen != e2->querylen) {
        return 0;
    }
    _dnsPacket_init(pack1, e1->query, e1->querylen);
    _dnsPacket_init(pack2, e2->query, e2->querylen);

    return _dnsPacket_isEqualQuery(pack1, pack2);
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* We use a simple hash table with external collision lists
 * for simplicity, the hash-table fields 'hash' and 'hlink' are
 * inlined in the Entry structure.
 */

/* Maximum time for a thread to wait for an pending request */
#define PENDING_REQUEST_TIMEOUT 20;

typedef struct pending_req_info {
    unsigned int                hash;
    pthread_cond_t              cond;
    struct pending_req_info*    next;
} PendingReqInfo;

typedef struct resolv_cache {
    int              max_entries;
    int              num_entries;
    Entry            mru_list;
    int              last_id;
    Entry*           entries;
    PendingReqInfo   pending_requests;
} Cache;

struct resolv_cache_info {
    unsigned                    netid;
    Cache*                      cache;
    struct resolv_cache_info*   next;
    int                         nscount;
    char*                       nameservers[MAXNS];
    struct addrinfo*            nsaddrinfo[MAXNS];
    int                         revision_id; // # times the nameservers have been replaced
    struct __res_params         params;
    struct __res_stats          nsstats[MAXNS];
    char                        defdname[MAXDNSRCHPATH];
    int                         dnsrch_offset[MAXDNSRCH+1];  // offsets into defdname
};

#define  HTABLE_VALID(x)  ((x) != NULL && (x) != HTABLE_DELETED)

static pthread_once_t        _res_cache_once = PTHREAD_ONCE_INIT;
static void _res_cache_init(void);

// lock protecting everything in the _resolve_cache_info structs (next ptr, etc)
static pthread_mutex_t _res_cache_list_lock;

/* gets cache associated with a network, or NULL if none exists */
static struct resolv_cache* _find_named_cache_locked(unsigned netid);

static void
_cache_flush_pending_requests_locked( struct resolv_cache* cache )
{
    struct pending_req_info *ri, *tmp;
    if (cache) {
        ri = cache->pending_requests.next;

        while (ri) {
            tmp = ri;
            ri = ri->next;
            pthread_cond_broadcast(&tmp->cond);

            pthread_cond_destroy(&tmp->cond);
            free(tmp);
        }

        cache->pending_requests.next = NULL;
    }
}

/* Return 0 if no pending request is found matching the key.
 * If a matching request is found the calling thread will wait until
 * the matching request completes, then update *cache and return 1. */
static int
_cache_check_pending_request_locked( struct resolv_cache** cache, Entry* key, unsigned netid )
{
    struct pending_req_info *ri, *prev;
    int exist = 0;

    if (*cache && key) {
        ri = (*cache)->pending_requests.next;
        prev = &(*cache)->pending_requests;
        while (ri) {
            if (ri->hash == key->hash) {
                exist = 1;
                break;
            }
            prev = ri;
            ri = ri->next;
        }

        if (!exist) {
            ri = calloc(1, sizeof(struct pending_req_info));
            if (ri) {
                ri->hash = key->hash;
                pthread_cond_init(&ri->cond, NULL);
                prev->next = ri;
            }
        } else {
            struct timespec ts = {0,0};
            XLOG("Waiting for previous request");
            ts.tv_sec = _time_now() + PENDING_REQUEST_TIMEOUT;
            pthread_cond_timedwait(&ri->cond, &_res_cache_list_lock, &ts);
            /* Must update *cache as it could have been deleted. */
            *cache = _find_named_cache_locked(netid);
        }
    }

    return exist;
}

/* notify any waiting thread that waiting on a request
 * matching the key has been added to the cache */
static void
_cache_notify_waiting_tid_locked( struct resolv_cache* cache, Entry* key )
{
    struct pending_req_info *ri, *prev;

    if (cache && key) {
        ri = cache->pending_requests.next;
        prev = &cache->pending_requests;
        while (ri) {
            if (ri->hash == key->hash) {
                pthread_cond_broadcast(&ri->cond);
                break;
            }
            prev = ri;
            ri = ri->next;
        }

        // remove item from list and destroy
        if (ri) {
            prev->next = ri->next;
            pthread_cond_destroy(&ri->cond);
            free(ri);
        }
    }
}

/* notify the cache that the query failed */
void
_resolv_cache_query_failed( unsigned    netid,
                   const void* query,
                   int         querylen)
{
    Entry    key[1];
    Cache*   cache;

    if (!entry_init_key(key, query, querylen))
        return;

    pthread_mutex_lock(&_res_cache_list_lock);

    cache = _find_named_cache_locked(netid);

    if (cache) {
        _cache_notify_waiting_tid_locked(cache, key);
    }

    pthread_mutex_unlock(&_res_cache_list_lock);
}

static struct resolv_cache_info* _find_cache_info_locked(unsigned netid);

static void
_cache_flush_locked( Cache*  cache )
{
    int     nn;

    for (nn = 0; nn < cache->max_entries; nn++)
    {
        Entry**  pnode = (Entry**) &cache->entries[nn];

        while (*pnode != NULL) {
            Entry*  node = *pnode;
            *pnode = node->hlink;
            entry_free(node);
        }
    }

    // flush pending request
    _cache_flush_pending_requests_locked(cache);

    cache->mru_list.mru_next = cache->mru_list.mru_prev = &cache->mru_list;
    cache->num_entries       = 0;
    cache->last_id           = 0;

    XLOG("*************************\n"
         "*** DNS CACHE FLUSHED ***\n"
         "*************************");
}

static int
_res_cache_get_max_entries( void )
{
    int cache_size = CONFIG_MAX_ENTRIES;

    const char* cache_mode = getenv("ANDROID_DNS_MODE");
    if (cache_mode == NULL || strcmp(cache_mode, "local") != 0) {
        // Don't use the cache in local mode. This is used by the proxy itself.
        cache_size = 0;
    }

    XLOG("cache size: %d", cache_size);
    return cache_size;
}

static struct resolv_cache*
_resolv_cache_create( void )
{
    struct resolv_cache*  cache;

    cache = calloc(sizeof(*cache), 1);
    if (cache) {
        cache->max_entries = _res_cache_get_max_entries();
        cache->entries = calloc(sizeof(*cache->entries), cache->max_entries);
        if (cache->entries) {
            cache->mru_list.mru_prev = cache->mru_list.mru_next = &cache->mru_list;
            XLOG("%s: cache created\n", __FUNCTION__);
        } else {
            free(cache);
            cache = NULL;
        }
    }
    return cache;
}


#if DEBUG
static void
_dump_query( const uint8_t*  query, int  querylen )
{
    char       temp[256], *p=temp, *end=p+sizeof(temp);
    DnsPacket  pack[1];

    _dnsPacket_init(pack, query, querylen);
    p = _dnsPacket_bprintQuery(pack, p, end);
    XLOG("QUERY: %s", temp);
}

static void
_cache_dump_mru( Cache*  cache )
{
    char    temp[512], *p=temp, *end=p+sizeof(temp);
    Entry*  e;

    p = _bprint(temp, end, "MRU LIST (%2d): ", cache->num_entries);
    for (e = cache->mru_list.mru_next; e != &cache->mru_list; e = e->mru_next)
        p = _bprint(p, end, " %d", e->id);

    XLOG("%s", temp);
}

static void
_dump_answer(const void* answer, int answerlen)
{
    res_state statep;
    FILE* fp;
    char* buf;
    int fileLen;

    fp = fopen("/data/reslog.txt", "w+e");
    if (fp != NULL) {
        statep = __res_get_state();

        res_pquery(statep, answer, answerlen, fp);

        //Get file length
        fseek(fp, 0, SEEK_END);
        fileLen=ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buf = (char *)malloc(fileLen+1);
        if (buf != NULL) {
            //Read file contents into buffer
            fread(buf, fileLen, 1, fp);
            XLOG("%s\n", buf);
            free(buf);
        }
        fclose(fp);
        remove("/data/reslog.txt");
    }
    else {
        errno = 0; // else debug is introducing error signals
        XLOG("%s: can't open file\n", __FUNCTION__);
    }
}
#endif

#if DEBUG
#  define  XLOG_QUERY(q,len)   _dump_query((q), (len))
#  define  XLOG_ANSWER(a, len) _dump_answer((a), (len))
#else
#  define  XLOG_QUERY(q,len)   ((void)0)
#  define  XLOG_ANSWER(a,len)  ((void)0)
#endif

/* This function tries to find a key within the hash table
 * In case of success, it will return a *pointer* to the hashed key.
 * In case of failure, it will return a *pointer* to NULL
 *
 * So, the caller must check '*result' to check for success/failure.
 *
 * The main idea is that the result can later be used directly in
 * calls to _resolv_cache_add or _resolv_cache_remove as the 'lookup'
 * parameter. This makes the code simpler and avoids re-searching
 * for the key position in the htable.
 *
 * The result of a lookup_p is only valid until you alter the hash
 * table.
 */
static Entry**
_cache_lookup_p( Cache*   cache,
                 Entry*   key )
{
    int      index = key->hash % cache->max_entries;
    Entry**  pnode = (Entry**) &cache->entries[ index ];

    while (*pnode != NULL) {
        Entry*  node = *pnode;

        if (node == NULL)
            break;

        if (node->hash == key->hash && entry_equals(node, key))
            break;

        pnode = &node->hlink;
    }
    return pnode;
}

/* Add a new entry to the hash table. 'lookup' must be the
 * result of an immediate previous failed _lookup_p() call
 * (i.e. with *lookup == NULL), and 'e' is the pointer to the
 * newly created entry
 */
static void
_cache_add_p( Cache*   cache,
              Entry**  lookup,
              Entry*   e )
{
    *lookup = e;
    e->id = ++cache->last_id;
    entry_mru_add(e, &cache->mru_list);
    cache->num_entries += 1;

    XLOG("%s: entry %d added (count=%d)", __FUNCTION__,
         e->id, cache->num_entries);
}

/* Remove an existing entry from the hash table,
 * 'lookup' must be the result of an immediate previous
 * and succesful _lookup_p() call.
 */
static void
_cache_remove_p( Cache*   cache,
                 Entry**  lookup )
{
    Entry*  e  = *lookup;

    XLOG("%s: entry %d removed (count=%d)", __FUNCTION__,
         e->id, cache->num_entries-1);

    entry_mru_remove(e);
    *lookup = e->hlink;
    entry_free(e);
    cache->num_entries -= 1;
}

/* Remove the oldest entry from the hash table.
 */
static void
_cache_remove_oldest( Cache*  cache )
{
    Entry*   oldest = cache->mru_list.mru_prev;
    Entry**  lookup = _cache_lookup_p(cache, oldest);

    if (*lookup == NULL) { /* should not happen */
        XLOG("%s: OLDEST NOT IN HTABLE ?", __FUNCTION__);
        return;
    }
    if (DEBUG) {
        XLOG("Cache full - removing oldest");
        XLOG_QUERY(oldest->query, oldest->querylen);
    }
    _cache_remove_p(cache, lookup);
}

/* Remove all expired entries from the hash table.
 */
static void _cache_remove_expired(Cache* cache) {
    Entry* e;
    time_t now = _time_now();

    for (e = cache->mru_list.mru_next; e != &cache->mru_list;) {
        // Entry is old, remove
        if (now >= e->expires) {
            Entry** lookup = _cache_lookup_p(cache, e);
            if (*lookup == NULL) { /* should not happen */
                XLOG("%s: ENTRY NOT IN HTABLE ?", __FUNCTION__);
                return;
            }
            e = e->mru_next;
            _cache_remove_p(cache, lookup);
        } else {
            e = e->mru_next;
        }
    }
}

ResolvCacheStatus
_resolv_cache_lookup( unsigned              netid,
                      const void*           query,
                      int                   querylen,
                      void*                 answer,
                      int                   answersize,
                      int                  *answerlen )
{
    Entry      key[1];
    Entry**    lookup;
    Entry*     e;
    time_t     now;
    Cache*     cache;

    ResolvCacheStatus  result = RESOLV_CACHE_NOTFOUND;

    XLOG("%s: lookup", __FUNCTION__);
    XLOG_QUERY(query, querylen);

    /* we don't cache malformed queries */
    if (!entry_init_key(key, query, querylen)) {
        XLOG("%s: unsupported query", __FUNCTION__);
        return RESOLV_CACHE_UNSUPPORTED;
    }
    /* lookup cache */
    pthread_once(&_res_cache_once, _res_cache_init);
    pthread_mutex_lock(&_res_cache_list_lock);

    cache = _find_named_cache_locked(netid);
    if (cache == NULL) {
        result = RESOLV_CACHE_UNSUPPORTED;
        goto Exit;
    }

    /* see the description of _lookup_p to understand this.
     * the function always return a non-NULL pointer.
     */
    lookup = _cache_lookup_p(cache, key);
    e      = *lookup;

    if (e == NULL) {
        XLOG( "NOT IN CACHE");
        // calling thread will wait if an outstanding request is found
        // that matching this query
        if (!_cache_check_pending_request_locked(&cache, key, netid) || cache == NULL) {
            goto Exit;
        } else {
            lookup = _cache_lookup_p(cache, key);
            e = *lookup;
            if (e == NULL) {
                goto Exit;
            }
        }
    }

    now = _time_now();

    /* remove stale entries here */
    if (now >= e->expires) {
        XLOG( " NOT IN CACHE (STALE ENTRY %p DISCARDED)", *lookup );
        XLOG_QUERY(e->query, e->querylen);
        _cache_remove_p(cache, lookup);
        goto Exit;
    }

    *answerlen = e->answerlen;
    if (e->answerlen > answersize) {
        /* NOTE: we return UNSUPPORTED if the answer buffer is too short */
        result = RESOLV_CACHE_UNSUPPORTED;
        XLOG(" ANSWER TOO LONG");
        goto Exit;
    }

    memcpy( answer, e->answer, e->answerlen );

    /* bump up this entry to the top of the MRU list */
    if (e != cache->mru_list.mru_next) {
        entry_mru_remove( e );
        entry_mru_add( e, &cache->mru_list );
    }

    XLOG( "FOUND IN CACHE entry=%p", e );
    result = RESOLV_CACHE_FOUND;

Exit:
    pthread_mutex_unlock(&_res_cache_list_lock);
    return result;
}


void
_resolv_cache_add( unsigned              netid,
                   const void*           query,
                   int                   querylen,
                   const void*           answer,
                   int                   answerlen )
{
    Entry    key[1];
    Entry*   e;
    Entry**  lookup;
    u_long   ttl;
    Cache*   cache = NULL;

    /* don't assume that the query has already been cached
     */
    if (!entry_init_key( key, query, querylen )) {
        XLOG( "%s: passed invalid query ?", __FUNCTION__);
        return;
    }

    pthread_mutex_lock(&_res_cache_list_lock);

    cache = _find_named_cache_locked(netid);
    if (cache == NULL) {
        goto Exit;
    }

    XLOG( "%s: query:", __FUNCTION__ );
    XLOG_QUERY(query,querylen);
    XLOG_ANSWER(answer, answerlen);
#if DEBUG_DATA
    XLOG( "answer:");
    XLOG_BYTES(answer,answerlen);
#endif

    lookup = _cache_lookup_p(cache, key);
    e      = *lookup;

    if (e != NULL) { /* should not happen */
        XLOG("%s: ALREADY IN CACHE (%p) ? IGNORING ADD",
             __FUNCTION__, e);
        goto Exit;
    }

    if (cache->num_entries >= cache->max_entries) {
        _cache_remove_expired(cache);
        if (cache->num_entries >= cache->max_entries) {
            _cache_remove_oldest(cache);
        }
        /* need to lookup again */
        lookup = _cache_lookup_p(cache, key);
        e      = *lookup;
        if (e != NULL) {
            XLOG("%s: ALREADY IN CACHE (%p) ? IGNORING ADD",
                __FUNCTION__, e);
            goto Exit;
        }
    }

    ttl = answer_getTTL(answer, answerlen);
    if (ttl > 0) {
        e = entry_alloc(key, answer, answerlen);
        if (e != NULL) {
            e->expires = ttl + _time_now();
            _cache_add_p(cache, lookup, e);
        }
    }
#if DEBUG
    _cache_dump_mru(cache);
#endif
Exit:
    if (cache != NULL) {
      _cache_notify_waiting_tid_locked(cache, key);
    }
    pthread_mutex_unlock(&_res_cache_list_lock);
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

// Head of the list of caches.  Protected by _res_cache_list_lock.
static struct resolv_cache_info _res_cache_list;

/* insert resolv_cache_info into the list of resolv_cache_infos */
static void _insert_cache_info_locked(struct resolv_cache_info* cache_info);
/* creates a resolv_cache_info */
static struct resolv_cache_info* _create_cache_info( void );
/* gets a resolv_cache_info associated with a network, or NULL if not found */
static struct resolv_cache_info* _find_cache_info_locked(unsigned netid);
/* look up the named cache, and creates one if needed */
static struct resolv_cache* _get_res_cache_for_net_locked(unsigned netid);
/* empty the named cache */
static void _flush_cache_for_net_locked(unsigned netid);
/* empty the nameservers set for the named cache */
static void _free_nameservers_locked(struct resolv_cache_info* cache_info);
/* return 1 if the provided list of name servers differs from the list of name servers
 * currently attached to the provided cache_info */
static int _resolv_is_nameservers_equal_locked(struct resolv_cache_info* cache_info,
        const char** servers, int numservers);
/* clears the stats samples contained withing the given cache_info */
static void _res_cache_clear_stats_locked(struct resolv_cache_info* cache_info);

static void
_res_cache_init(void)
{
    memset(&_res_cache_list, 0, sizeof(_res_cache_list));
    pthread_mutex_init(&_res_cache_list_lock, NULL);
}

static struct resolv_cache*
_get_res_cache_for_net_locked(unsigned netid)
{
    struct resolv_cache* cache = _find_named_cache_locked(netid);
    if (!cache) {
        struct resolv_cache_info* cache_info = _create_cache_info();
        if (cache_info) {
            cache = _resolv_cache_create();
            if (cache) {
                cache_info->cache = cache;
                cache_info->netid = netid;
                _insert_cache_info_locked(cache_info);
            } else {
                free(cache_info);
            }
        }
    }
    return cache;
}

void
_resolv_flush_cache_for_net(unsigned netid)
{
    pthread_once(&_res_cache_once, _res_cache_init);
    pthread_mutex_lock(&_res_cache_list_lock);

    _flush_cache_for_net_locked(netid);

    pthread_mutex_unlock(&_res_cache_list_lock);
}

static void
_flush_cache_for_net_locked(unsigned netid)
{
    struct resolv_cache* cache = _find_named_cache_locked(netid);
    if (cache) {
        _cache_flush_locked(cache);
    }

    // Also clear the NS statistics.
    struct resolv_cache_info* cache_info = _find_cache_info_locked(netid);
    _res_cache_clear_stats_locked(cache_info);
}

void _resolv_delete_cache_for_net(unsigned netid)
{
    pthread_once(&_res_cache_once, _res_cache_init);
    pthread_mutex_lock(&_res_cache_list_lock);

    struct resolv_cache_info* prev_cache_info = &_res_cache_list;

    while (prev_cache_info->next) {
        struct resolv_cache_info* cache_info = prev_cache_info->next;

        if (cache_info->netid == netid) {
            prev_cache_info->next = cache_info->next;
            _cache_flush_locked(cache_info->cache);
            free(cache_info->cache->entries);
            free(cache_info->cache);
            _free_nameservers_locked(cache_info);
            free(cache_info);
            break;
        }

        prev_cache_info = prev_cache_info->next;
    }

    pthread_mutex_unlock(&_res_cache_list_lock);
}

static struct resolv_cache_info*
_create_cache_info(void)
{
    struct resolv_cache_info* cache_info;

    cache_info = calloc(sizeof(*cache_info), 1);
    return cache_info;
}

static void
_insert_cache_info_locked(struct resolv_cache_info* cache_info)
{
    struct resolv_cache_info* last;

    for (last = &_res_cache_list; last->next; last = last->next);

    last->next = cache_info;

}

static struct resolv_cache*
_find_named_cache_locked(unsigned netid) {

    struct resolv_cache_info* info = _find_cache_info_locked(netid);

    if (info != NULL) return info->cache;

    return NULL;
}

static struct resolv_cache_info*
_find_cache_info_locked(unsigned netid)
{
    struct resolv_cache_info* cache_info = _res_cache_list.next;

    while (cache_info) {
        if (cache_info->netid == netid) {
            break;
        }

        cache_info = cache_info->next;
    }
    return cache_info;
}

void
_resolv_set_default_params(struct __res_params* params) {
    params->sample_validity = NSSAMPLE_VALIDITY;
    params->success_threshold = SUCCESS_THRESHOLD;
    params->min_samples = 0;
    params->max_samples = 0;
    params->base_timeout_msec = 0;  // 0 = legacy algorithm
}

int
_resolv_set_nameservers_for_net(unsigned netid, const char** servers, unsigned numservers,
        const char *domains, const struct __res_params* params)
{
    char sbuf[NI_MAXSERV];
    register char *cp;
    int *offset;
    struct addrinfo* nsaddrinfo[MAXNS];

    if (numservers > MAXNS) {
        XLOG("%s: numservers=%u, MAXNS=%u", __FUNCTION__, numservers, MAXNS);
        return E2BIG;
    }

    // Parse the addresses before actually locking or changing any state, in case there is an error.
    // As a side effect this also reduces the time the lock is kept.
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_flags = AI_NUMERICHOST
    };
    snprintf(sbuf, sizeof(sbuf), "%u", NAMESERVER_PORT);
    for (unsigned i = 0; i < numservers; i++) {
        // The addrinfo structures allocated here are freed in _free_nameservers_locked().
        int rt = getaddrinfo(servers[i], sbuf, &hints, &nsaddrinfo[i]);
        if (rt != 0) {
            for (unsigned j = 0 ; j < i ; j++) {
                freeaddrinfo(nsaddrinfo[j]);
                nsaddrinfo[j] = NULL;
            }
            XLOG("%s: getaddrinfo(%s)=%s", __FUNCTION__, servers[i], gai_strerror(rt));
            return EINVAL;
        }
    }

    pthread_once(&_res_cache_once, _res_cache_init);
    pthread_mutex_lock(&_res_cache_list_lock);

    // creates the cache if not created
    _get_res_cache_for_net_locked(netid);

    struct resolv_cache_info* cache_info = _find_cache_info_locked(netid);

    if (cache_info != NULL) {
        uint8_t old_max_samples = cache_info->params.max_samples;
        if (params != NULL) {
            cache_info->params = *params;
        } else {
            _resolv_set_default_params(&cache_info->params);
        }

        if (!_resolv_is_nameservers_equal_locked(cache_info, servers, numservers)) {
            // free current before adding new
            _free_nameservers_locked(cache_info);
            unsigned i;
            for (i = 0; i < numservers; i++) {
                cache_info->nsaddrinfo[i] = nsaddrinfo[i];
                cache_info->nameservers[i] = strdup(servers[i]);
                XLOG("%s: netid = %u, addr = %s\n", __FUNCTION__, netid, servers[i]);
            }
            cache_info->nscount = numservers;

            // Clear the NS statistics because the mapping to nameservers might have changed.
            _res_cache_clear_stats_locked(cache_info);

            // increment the revision id to ensure that sample state is not written back if the
            // servers change; in theory it would suffice to do so only if the servers or
            // max_samples actually change, in practice the overhead of checking is higher than the
            // cost, and overflows are unlikely
            ++cache_info->revision_id;
        } else {
            if (cache_info->params.max_samples != old_max_samples) {
                // If the maximum number of samples changes, the overhead of keeping the most recent
                // samples around is not considered worth the effort, so they are cleared instead.
                // All other parameters do not affect shared state: Changing these parameters does
                // not invalidate the samples, as they only affect aggregation and the conditions
                // under which servers are considered usable.
                _res_cache_clear_stats_locked(cache_info);
                ++cache_info->revision_id;
            }
            for (unsigned j = 0; j < numservers; j++) {
                freeaddrinfo(nsaddrinfo[j]);
            }
        }

        // Always update the search paths, since determining whether they actually changed is
        // complex due to the zero-padding, and probably not worth the effort. Cache-flushing
        // however is not // necessary, since the stored cache entries do contain the domain, not
        // just the host name.
        // code moved from res_init.c, load_domain_search_list
        strlcpy(cache_info->defdname, domains, sizeof(cache_info->defdname));
        if ((cp = strchr(cache_info->defdname, '\n')) != NULL)
            *cp = '\0';

        cp = cache_info->defdname;
        offset = cache_info->dnsrch_offset;
        while (offset < cache_info->dnsrch_offset + MAXDNSRCH) {
            while (*cp == ' ' || *cp == '\t') /* skip leading white space */
                cp++;
            if (*cp == '\0') /* stop if nothing more to do */
                break;
            *offset++ = cp - cache_info->defdname; /* record this search domain */
            while (*cp) { /* zero-terminate it */
                if (*cp == ' '|| *cp == '\t') {
                    *cp++ = '\0';
                    break;
                }
                cp++;
            }
        }
        *offset = -1; /* cache_info->dnsrch_offset has MAXDNSRCH+1 items */
    }

    pthread_mutex_unlock(&_res_cache_list_lock);
    return 0;
}

static int
_resolv_is_nameservers_equal_locked(struct resolv_cache_info* cache_info,
        const char** servers, int numservers)
{
    if (cache_info->nscount != numservers) {
        return 0;
    }

    // Compare each name server against current name servers.
    // TODO: this is incorrect if the list of current or previous nameservers
    // contains duplicates. This does not really matter because the framework
    // filters out duplicates, but we should probably fix it. It's also
    // insensitive to the order of the nameservers; we should probably fix that
    // too.
    for (int i = 0; i < numservers; i++) {
        for (int j = 0 ; ; j++) {
            if (j >= numservers) {
                return 0;
            }
            if (strcmp(cache_info->nameservers[i], servers[j]) == 0) {
                break;
            }
        }
    }

    return 1;
}

static void
_free_nameservers_locked(struct resolv_cache_info* cache_info)
{
    int i;
    for (i = 0; i < cache_info->nscount; i++) {
        free(cache_info->nameservers[i]);
        cache_info->nameservers[i] = NULL;
        if (cache_info->nsaddrinfo[i] != NULL) {
            freeaddrinfo(cache_info->nsaddrinfo[i]);
            cache_info->nsaddrinfo[i] = NULL;
        }
        cache_info->nsstats[i].sample_count =
            cache_info->nsstats[i].sample_next = 0;
    }
    cache_info->nscount = 0;
    _res_cache_clear_stats_locked(cache_info);
    ++cache_info->revision_id;
}

void
_resolv_populate_res_for_net(res_state statp)
{
    if (statp == NULL) {
        return;
    }

    pthread_once(&_res_cache_once, _res_cache_init);
    pthread_mutex_lock(&_res_cache_list_lock);

    struct resolv_cache_info* info = _find_cache_info_locked(statp->netid);
    if (info != NULL) {
        int nserv;
        struct addrinfo* ai;
        XLOG("%s: %u\n", __FUNCTION__, statp->netid);
        for (nserv = 0; nserv < MAXNS; nserv++) {
            ai = info->nsaddrinfo[nserv];
            if (ai == NULL) {
                break;
            }

            if ((size_t) ai->ai_addrlen <= sizeof(statp->_u._ext.ext->nsaddrs[0])) {
                if (statp->_u._ext.ext != NULL) {
                    memcpy(&statp->_u._ext.ext->nsaddrs[nserv], ai->ai_addr, ai->ai_addrlen);
                    statp->nsaddr_list[nserv].sin_family = AF_UNSPEC;
                } else {
                    if ((size_t) ai->ai_addrlen
                            <= sizeof(statp->nsaddr_list[0])) {
                        memcpy(&statp->nsaddr_list[nserv], ai->ai_addr,
                                ai->ai_addrlen);
                    } else {
                        statp->nsaddr_list[nserv].sin_family = AF_UNSPEC;
                    }
                }
            } else {
                XLOG("%s: found too long addrlen", __FUNCTION__);
            }
        }
        statp->nscount = nserv;
        // now do search domains.  Note that we cache the offsets as this code runs alot
        // but the setting/offset-computer only runs when set/changed
        // WARNING: Don't use str*cpy() here, this string contains zeroes.
        memcpy(statp->defdname, info->defdname, sizeof(statp->defdname));
        register char **pp = statp->dnsrch;
        register int *p = info->dnsrch_offset;
        while (pp < statp->dnsrch + MAXDNSRCH && *p != -1) {
            *pp++ = &statp->defdname[0] + *p++;
        }
    }
    pthread_mutex_unlock(&_res_cache_list_lock);
}

/* Resolver reachability statistics. */

static void
_res_cache_add_stats_sample_locked(struct __res_stats* stats, const struct __res_sample* sample,
        int max_samples) {
    // Note: This function expects max_samples > 0, otherwise a (harmless) modification of the
    // allocated but supposedly unused memory for samples[0] will happen
    XLOG("%s: adding sample to stats, next = %d, count = %d", __FUNCTION__,
            stats->sample_next, stats->sample_count);
    stats->samples[stats->sample_next] = *sample;
    if (stats->sample_count < max_samples) {
        ++stats->sample_count;
    }
    if (++stats->sample_next >= max_samples) {
        stats->sample_next = 0;
    }
}

static void
_res_cache_clear_stats_locked(struct resolv_cache_info* cache_info) {
    if (cache_info) {
        for (int i = 0 ; i < MAXNS ; ++i) {
"""


```