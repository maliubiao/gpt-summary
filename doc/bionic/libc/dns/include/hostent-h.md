Response:
Let's break down the thought process for analyzing the `hostent.h` header file and addressing the prompt's requirements.

**1. Understanding the Core Purpose:**

The first step is to recognize that this header file is part of the C standard library (libc) within the DNS subsystem. The file name `hostent.h` strongly suggests it deals with host entry information, a fundamental concept in networking. The copyright notice confirms its origin in NetBSD and its use within Android's Bionic library.

**2. Identifying Key Components:**

Scanning the file, I look for the main building blocks:

* **Includes:** `stdio.h`, `netdb.h`, `stdarg.h`. This tells me it uses standard input/output, network database definitions (crucially, the `hostent` struct itself), and variable arguments.
* **Function Declarations:**  `sethostent_r`, `netbsd_gethostent_r`, `endhostent_r`. The `_r` suffix immediately signals thread-safe, reentrant versions of standard functions. The prefix `netbsd_` hints at its origin or potential differences from standard versions.
* **Structure Definition:** `struct getnamaddr`. This appears to be an internal structure likely used for managing state within the reentrant functions.
* **Function Declarations (Internal):** `_hf_gethtbyaddr`, `_hf_gethtbyname`, `_yp_gethtbyaddr`, `_yp_gethtbyname`. The `_` prefix indicates internal or private functions. The `hf` likely stands for "hosts file", and `yp` for "Yellow Pages" (NIS), revealing different lookup sources.
* **Macros:** `HENT_ARRAY`, `HENT_COPY`, `HENT_SCOPY`. These macros manage memory allocation and copying for host entry data, with error handling (`goto nospc`).

**3. Addressing the Prompt's Questions Systematically:**

Now, I go through the prompt's questions one by one, using the identified components:

* **功能列举:** This is straightforward. List the declared functions, the structure, and the macros. Emphasize the thread-safe nature of the `_r` functions.
* **与 Android 功能的关系:** Connect the `hostent` structure and the functions to the core Android networking functionality: hostname resolution (converting names to IP addresses) and reverse DNS lookup. Give examples of how apps use hostnames.
* **libc 函数实现 (详细解释):**  This requires more deduction as only declarations are present.
    * `sethostent_r`:  Hypothesize that it opens the hosts file (or initializes a data source) in a thread-safe manner, potentially associating it with the provided `FILE**`.
    * `netbsd_gethostent_r`:  Explain its role in retrieving host information, emphasizing its reentrant nature using the provided buffer and error pointer. Mention the likely internal calls to the `_hf_` and `_yp_` functions.
    * `endhostent_r`:  Assume it closes the file or releases resources associated with the host entry data source.
    * For the internal `_hf_` and `_yp_` functions, explain their specific roles in looking up information in the hosts file and NIS, respectively. Note that they use `va_list` for flexibility.
* **dynamic linker 功能 (涉及):**  The header file *itself* doesn't directly perform dynamic linking. However, the *functions declared here* are part of libc, which is a shared library linked dynamically. Therefore, I need to explain:
    * The role of the dynamic linker in finding and loading shared libraries like libc.
    * The concept of symbol resolution, where function calls are linked to the actual function implementations in the loaded library.
    * Provide a typical `libc.so` layout with relevant sections (.text, .data, .bss, .dynsym, .dynstr).
    * Describe the linking process (lookup in DT_NEEDED, symbol table search, PLT/GOT).
* **逻辑推理 (假设输入与输出):** Focus on `netbsd_gethostent_r`. Provide a sample hostname as input and describe the expected output (the `hostent` structure populated with relevant information). Mention potential errors (hostname not found).
* **用户/编程常见错误:** Common mistakes involve buffer overflows (not using the provided size), thread-safety issues (using non-reentrant functions in multithreaded code), and incorrect error handling.
* **Android Framework/NDK 到达这里:** Trace the path:
    * Android app uses Java networking APIs (`InetAddress`).
    * These APIs call native methods in the Android framework.
    * The framework calls Bionic libc functions (like `getaddrinfo`, which in turn might call `gethostbyname_r` which likely uses the functions declared here).
    * NDK:  Native code can directly call Bionic libc functions, including those defined in this header.
* **Frida Hook 示例:** Provide a Frida snippet targeting `netbsd_gethostent_r`. Demonstrate how to hook the function, log arguments, and potentially modify the return value.

**4. Refinement and Language:**

Finally, review the entire response for clarity, accuracy, and completeness. Ensure the language is precise and understandable. Use Chinese as requested in the prompt. Pay attention to phrasing and logical flow. For instance, clearly distinguish between the header file's contents and the actual implementation of the functions it declares. Also, make sure the examples are relevant and easy to follow.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific macros. Realizing they are just memory management helpers within these functions helps to prioritize the core function declarations.
* I might have overlooked the connection to dynamic linking initially. Connecting the declared functions to their existence within a shared library is a key step.
* Ensuring the Frida example is functional and targets the correct function is crucial. Double-checking the function name is important.
*  Making sure the explanation of the dynamic linking process includes the key components like PLT and GOT.

By following this structured approach, considering the prompt's requirements carefully, and performing necessary deductions based on the available information, a comprehensive and accurate answer can be generated.
这是一个位于 Android Bionic 库中 DNS 相关的头文件 `hostent.handroid`。它定义了一些用于处理主机条目的结构体和函数声明。虽然文件名包含 `.handroid`，这通常表示 Android 特有的修改或扩展，但从内容来看，它主要还是围绕着标准的 `hostent` 结构体以及一些线程安全的变体。

**功能列举:**

该头文件主要定义了以下功能：

1. **线程安全的 `hostent` 相关函数声明:**
   - `sethostent_r(FILE **)`:  一个线程安全的版本，用于打开主机名数据库。它接受一个指向 `FILE*` 的指针的指针，用于存储内部状态。
   - `netbsd_gethostent_r(FILE *, struct hostent *, char *, size_t, int *)`:  一个线程安全的版本，用于从打开的主机名数据库中读取下一个主机条目。它需要用户提供的 `hostent` 结构体、缓冲区以及错误码指针。
   - `endhostent_r(FILE **)`:  一个线程安全的版本，用于关闭主机名数据库。

2. **内部使用的结构体:**
   - `struct getnamaddr`:  这个结构体似乎是为了内部使用而设计的，可能用于在主机名和地址之间进行查找操作时传递上下文信息，包含 `hostent` 指针、缓冲区和错误码指针。

3. **内部使用的查找函数声明:**
   - `_hf_gethtbyaddr(void *, void *, va_list)`:  从 `/etc/hosts` 文件中根据 IP 地址查找主机信息的内部函数。
   - `_hf_gethtbyname(void *, void *, va_list)`:  从 `/etc/hosts` 文件中根据主机名查找主机信息的内部函数。
   - `_yp_gethtbyaddr(void *, void *, va_list)`:  （如果定义了 `YP`）从 NIS (Network Information Service) 中根据 IP 地址查找主机信息的内部函数。
   - `_yp_gethtbyname(void *, void *, va_list)`:  （如果定义了 `YP`）从 NIS 中根据主机名查找主机信息的内部函数。
   这些函数都使用了 `va_list`，这表明它们可能被设计为由其他辅助函数调用，并接受可变数量的参数。

4. **辅助宏定义:**
   - `HENT_ARRAY(dst, anum, ptr, len)`:  用于在提供的缓冲区中分配存储主机地址列表的数组空间。
   - `HENT_COPY(dst, src, slen, ptr, len)`:  用于将数据复制到提供的缓冲区中。
   - `HENT_SCOPY(dst, src, ptr, len)`:  用于将以 null 结尾的字符串复制到提供的缓冲区中。
   这些宏都包含了一个 `goto nospc;` 语句，表明在缓冲区空间不足时会跳转到标签 `nospc` 进行错误处理（尽管这个标签本身并没有在这个头文件中定义，它应该在调用这些宏的代码中定义）。

**与 Android 功能的关系及举例说明:**

这个头文件与 Android 的网络功能密切相关。Android 应用需要能够将主机名（如 `www.google.com`) 转换为 IP 地址 (如 `172.217.160.142`)，以及反过来将 IP 地址转换为主机名。这些操作依赖于底层的 DNS 解析机制。

- **`gethostbyname` 和 `gethostbyaddr` 的线程安全版本:**  Android 应用或系统服务在进行网络通信时，通常会调用 `gethostbyname` 或 `gethostbyaddr` 函数来执行 DNS 查询。由于 Android 是一个多线程环境，使用线程安全的 `_r` 版本（如 `gethostbyname_r` 和 `gethostbyaddr_r`，虽然这里声明的是 NetBSD 特有的 `netbsd_gethostent_r`，但其目的类似）是非常重要的，以避免竞态条件和数据损坏。
- **`/etc/hosts` 文件查找:**  `_hf_gethtbyname` 和 `_hf_gethtbyaddr` 表明 Android 的 DNS 解析过程会先检查本地的 `/etc/hosts` 文件。例如，开发者可以在 `/etc/hosts` 中手动添加一些主机名到 IP 地址的映射，方便本地测试或绕过某些 DNS 解析。
- **NIS (Network Information Service) 的可能性:**  尽管现在 NIS 不太常用，但 `_yp_gethtbyname` 和 `_yp_gethtbyaddr` 的存在表明 Bionic 库可能仍然保留了对 NIS 的支持，尽管在现代 Android 系统中可能默认不启用。

**举例说明:**

假设一个 Android 应用需要连接到 `www.example.com`。

1. 应用可能会调用 Java 网络 API，例如 `InetAddress.getByName("www.example.com")`。
2. Android Framework 接收到这个请求，并会调用底层的 Native 方法。
3. Native 方法最终会调用 Bionic libc 提供的 DNS 解析函数，例如 `getaddrinfo`。
4. `getaddrinfo` 内部可能会使用 `gethostbyname_r`（或者其内部实现会调用类似于 `netbsd_gethostent_r` 的函数）。
5. `netbsd_gethostent_r` 可能会先尝试从 `/etc/hosts` 文件中查找，这会涉及到调用 `_hf_gethtbyname`。
6. 如果在 `/etc/hosts` 中没有找到，它可能会继续查询配置的 DNS 服务器。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于这里只提供了头文件，我们只能推测这些函数的功能实现方式。通常，这些函数的实现会涉及以下步骤：

- **`sethostent_r(FILE **)`:**
    - 这个函数可能打开一个用于读取主机名信息的源，例如 `/etc/hosts` 文件或者通过网络连接到 DNS 服务器。
    - 为了线程安全，它可能需要维护一个与当前线程相关的状态信息，并将文件指针存储在 `FILE **` 指向的位置。这样，每个线程都有自己的文件句柄和读取位置。
    - **假设输入与输出:**  输入是一个未初始化的 `FILE*` 指针的地址。输出是该指针指向一个成功打开的文件流，或者如果失败则保持不变。

- **`netbsd_gethostent_r(FILE *, struct hostent *, char *, size_t, int *)`:**
    - 这个函数从之前通过 `sethostent_r` 打开的数据源中读取下一个主机条目。
    - 它需要一个预先分配的 `hostent` 结构体和缓冲区，以避免内存分配带来的线程安全问题。
    - 它会解析读取到的数据，并将主机名、别名、地址类型、地址长度和地址列表填充到提供的 `hostent` 结构体中。
    - 如果读取成功，错误码指针会设置为 0；如果发生错误（例如到达文件末尾或格式错误），则会设置相应的错误码。
    - **假设输入与输出:**
        - 输入：一个打开的文件流指针，一个空的 `hostent` 结构体，一个字符缓冲区及其大小，一个指向整数的指针用于存储错误码。
        - 输出：如果成功，`hostent` 结构体被填充，错误码为 0。如果失败（例如文件结束），`hostent` 结构体可能部分填充，错误码指示具体原因。

- **`endhostent_r(FILE **)`:**
    - 这个函数负责关闭通过 `sethostent_r` 打开的资源。
    - 它会将 `FILE **` 指向的指针设置为 `NULL`，并关闭相应的文件描述符或其他网络连接。
    - **假设输入与输出:** 输入是一个指向已打开文件流指针的指针。输出是文件流被关闭，并且输入的指针被设置为 `NULL`。

- **内部查找函数 (`_hf_gethtbyaddr`, `_hf_gethtbyname`, `_yp_gethtbyaddr`, `_yp_gethtbyname`):**
    - 这些函数是具体执行查找操作的实现。
    - 对于 `/etc/hosts` 文件 (`_hf_`)，它们会打开并逐行解析文件内容，匹配主机名或 IP 地址。
    - 对于 NIS (`_yp_`)，它们会使用 NIS 客户端库与 NIS 服务器通信来查询信息。
    - `va_list` 的使用表明这些函数可能被包装在更通用的查找接口中，允许根据不同的数据源进行查找。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然这个头文件本身不直接涉及 dynamic linker 的操作，但它声明的函数最终会被编译到 Bionic libc 库中，而 libc 是一个动态链接库。

**`libc.so` 布局样本:**

```
libc.so:
    .note.android.ident
    .plt                # Procedure Linkage Table
    .text               # 函数代码段 (包含 sethostent_r, netbsd_gethostent_r, endhostent_r 等的实现)
    .rodata             # 只读数据段
    .data               # 已初始化数据段
    .bss                # 未初始化数据段
    .dynamic            # 动态链接信息
    .symtab             # 符号表
    .strtab             # 字符串表
    .dynsym             # 动态符号表
    .dynstr             # 动态字符串表
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当一个程序（例如 Android 应用的 Native 代码）调用了 `sethostent_r` 等函数时，编译器会在生成目标文件时记录下对这些符号的引用。由于 libc 是一个共享库，这些引用是未解析的。
2. **加载时链接:** 当 Android 系统加载这个程序时，dynamic linker (通常是 `linker64` 或 `linker`) 负责处理动态链接。
3. **查找依赖库:** Dynamic linker 会检查程序依赖的共享库列表 (通常在 ELF 文件的 `DT_NEEDED` 标签中)。libc 是所有 Android 程序都依赖的库，因此 dynamic linker 会找到 `libc.so`。
4. **加载共享库:** Dynamic linker 将 `libc.so` 加载到内存中的某个地址空间。
5. **符号解析 (Symbol Resolution):**
   - 当程序执行到调用 `sethostent_r` 的指令时，实际上会跳转到 Procedure Linkage Table (PLT) 中的一个条目。
   - 第一次调用时，PLT 条目会跳转到 dynamic linker 中的一个解析函数。
   - Dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `sethostent_r` 这个符号。
   - 一旦找到，dynamic linker 会将 `sethostent_r` 函数的实际地址更新到 Global Offset Table (GOT) 中对应的条目。
   - 同时，PLT 条目也会被修改，使得后续的调用可以直接跳转到 GOT 中存储的 `sethostent_r` 的地址，而无需再次经过 dynamic linker。
6. **执行函数:**  现在，程序可以通过 GOT 中正确的地址来调用 `sethostent_r` 函数。

**逻辑推理 (假设输入与输出):**

假设我们调用 `netbsd_gethostent_r` 来查找主机名为 "localhost" 的信息。

**假设输入:**

- `fp`: 指向一个通过 `sethostent_r` 打开的 `/etc/hosts` 文件流。
- `ret`: 指向一个预先分配的 `struct hostent` 结构体的指针。
- `buf`: 指向一个预先分配的缓冲区。
- `buflen`: 缓冲区的大小。
- `h_errnop`: 指向一个整数的指针，用于存储错误码。

**预期输出:**

如果 `/etc/hosts` 文件中包含类似以下的条目：

```
127.0.0.1   localhost
::1         localhost
```

那么调用 `netbsd_gethostent_r` 可能会填充 `ret` 结构体如下：

- `ret->h_name`: "localhost"
- `ret->h_aliases`: 一个包含别名的 `char**` 数组，可能为空。
- `ret->h_addrtype`: `AF_INET` 或 `AF_INET6`
- `ret->h_length`: 4 (对于 IPv4) 或 16 (对于 IPv6)
- `ret->h_addr_list`: 一个包含指向 IP 地址的指针的 `char**` 数组，例如指向包含 `127.0.0.1` 或 `::1` 的内存。
- `*h_errnop`: 0 (表示成功)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **缓冲区溢出:**  如果传递给 `netbsd_gethostent_r` 的缓冲区 `buf` 太小，无法容纳主机名、别名和地址信息，会导致缓冲区溢出，覆盖其他内存区域，造成程序崩溃或安全漏洞。
   ```c
   struct hostent h;
   char buf[64]; // 缓冲区可能太小
   int herrno;
   FILE *fp;
   sethostent_r(&fp);
   netbsd_gethostent_r(fp, &h, buf, sizeof(buf), &herrno); // 可能溢出
   endhostent_r(&fp);
   ```

2. **未检查返回值和错误码:**  忽略 `netbsd_gethostent_r` 的返回值和 `h_errnop` 指向的错误码，可能导致程序在发生错误时继续执行，产生不可预测的结果。
   ```c
   struct hostent *h;
   int herrno;
   // ... 调用 gethostbyname_r ...
   // 没有检查 h 或 herrno 的值
   printf("Hostname: %s\n", h->h_name); // 如果查找失败，h可能为NULL，导致崩溃
   ```

3. **在多线程环境中使用非线程安全函数:** 虽然这个头文件定义了线程安全的版本，但如果程序员错误地使用了非线程安全的 `gethostbyname` 等函数，在多线程环境下可能会导致竞态条件。

4. **内存管理错误:**  `netbsd_gethostent_r` 使用用户提供的缓冲区，但程序员需要确保缓冲区足够大。不正确地管理缓冲区或忘记释放通过其他方式分配的内存也可能导致问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤:**

1. **Java 代码调用:** Android 应用通常使用 `java.net.InetAddress` 类来进行主机名解析。例如：
   ```java
   InetAddress address = InetAddress.getByName("www.google.com");
   ```

2. **Framework Native 方法调用:** `InetAddress.getByName()` 方法最终会调用 Android Framework 中的 Native 方法（通常在 `libnativehelper.so` 或 `libnetd_client.so` 中）。

3. **Bionic libc 调用:** Framework 的 Native 代码会调用 Bionic libc 提供的网络相关函数，例如 `getaddrinfo`。

4. **`getaddrinfo` 内部调用:** `getaddrinfo` 可能会调用 `gethostbyname_r` 或类似的线程安全函数来进行主机名查找。

5. **最终调用 `netbsd_gethostent_r`:**  `gethostbyname_r` 的实现可能会使用 `sethostent_r`、`netbsd_gethostent_r` 和 `endhostent_r` 这些函数来读取主机名信息（例如从 `/etc/hosts` 文件）。

**NDK 到达这里的步骤:**

1. **NDK 代码调用:** 使用 NDK 开发的 Native 代码可以直接调用 Bionic libc 提供的函数：
   ```c
   #include <netdb.h>
   #include <stdio.h>

   int main() {
       struct hostent *host = gethostbyname("www.example.com");
       if (host != NULL) {
           printf("Hostname: %s\n", host->h_name);
       }
       return 0;
   }
   ```
   或者，使用线程安全的版本：
   ```c
   #include <netdb.h>
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       struct hostent result;
       char buf[1024];
       int herrno;
       struct hostent *host_ptr;
       FILE *fp;

       sethostent_r(&fp);
       host_ptr = netbsd_gethostent_r(fp, &result, buf, sizeof(buf), &herrno);
       if (host_ptr != NULL) {
           printf("Hostname: %s\n", host_ptr->h_name);
       } else {
           printf("Error: %d\n", herrno);
       }
       endhostent_r(&fp);
       return 0;
   }
   ```

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook `netbsd_gethostent_r` 的示例：

```javascript
// attach 到目标进程
function hook_gethostent_r() {
    const moduleName = "libc.so";
    const functionName = "_ZN6androidLuni17OsNetSystemImpl16getaddrinfo_proxyEPKcS2_PK18addrinfo_android_ti"; // 假设 getaddrinfo_proxy 内部会调用到 hostent 相关函数

    const nativeGetaddrinfo = Module.findExportByName(moduleName, functionName);

    if (nativeGetaddrinfo) {
        Interceptor.attach(nativeGetaddrinfo, {
            onEnter: function (args) {
                console.log("[getaddrinfo_proxy] Called");
                console.log("\thostname: " + args[0].readCString());
                console.log("\tservname: " + args[1].readCString());
            },
            onLeave: function (retval) {
                console.log("[getaddrinfo_proxy] Returning: " + retval);
            }
        });
        console.log("[getaddrinfo_proxy] Hooked!");
    } else {
        console.log("[getaddrinfo_proxy] Not found");
    }

    // Hook netbsd_gethostent_r
    const netbsd_gethostent_r_ptr = Module.findExportByName(moduleName, "netbsd_gethostent_r");
    if (netbsd_gethostent_r_ptr) {
        Interceptor.attach(netbsd_gethostent_r_ptr, {
            onEnter: function (args) {
                console.log("[netbsd_gethostent_r] Called");
                // args[0] 是 FILE *
                // args[1] 是 struct hostent *
                // args[2] 是 char * buf
                console.log("\tBuffer size: " + args[3]);
                // args[4] 是 int * herrno
            },
            onLeave: function (retval) {
                console.log("[netbsd_gethostent_r] Returning: " + retval);
                if (retval != 0) {
                    const hostentPtr = ptr(retval);
                    console.log("\th_name: " + hostentPtr.readPointer().readCString()); // 读取 h_name
                }
            }
        });
        console.log("[netbsd_gethostent_r] Hooked!");
    } else {
        console.log("[netbsd_gethostent_r] Not found");
    }
}

setTimeout(hook_gethostent_r, 1000); // 延迟 hook，确保模块加载完成
```

**Frida 调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 adb，并且手机已 root 并开启 USB 调试。
2. **找到目标进程:** 使用 `frida-ps -U` 找到你想要调试的应用进程 ID 或名称。
3. **运行 Frida 脚本:** 将上面的 JavaScript 代码保存为 `hook_dns.js`，然后使用以下命令运行：
   ```bash
   frida -U -f <package_name> -l hook_dns.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <process_id_or_name> -l hook_dns.js
   ```
4. **触发 DNS 查询:** 在目标应用中执行触发 DNS 查询的操作，例如访问一个网页或尝试连接到某个服务器。
5. **查看 Frida 输出:** Frida 会在控制台输出 `netbsd_gethostent_r` 函数被调用时的参数和返回值，你可以观察到缓冲区大小、以及返回的 `hostent` 结构体中的信息。

**注意:**

-  你需要根据实际情况找到 `getaddrinfo` 或其他相关函数的符号名称，Android 版本的 Bionic 库可能会有不同的命名方式。可以使用 `frida-trace` 或反汇编工具来辅助查找。
- Hook 动态链接库中的函数需要确保在函数被加载后进行，因此可以使用 `setTimeout` 延迟 Hook。
- 错误处理也很重要，例如检查 `Module.findExportByName` 的返回值，以避免因找不到函数而导致脚本错误。

通过以上分析和示例，你应该对 `bionic/libc/dns/include/hostent.handroid` 头文件的功能、与 Android 的关系、以及如何使用 Frida 进行调试有了更深入的理解。

### 提示词
```
这是目录为bionic/libc/dns/include/hostent.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*	$NetBSD: hostent.h,v 1.2 2013/08/27 09:56:12 christos Exp $	*/

/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _DNS_NET_HOSTENT_H
#define _DNS_NET_HOSTENT_H

#include <stdio.h>
#include <netdb.h>
#include <stdarg.h>

/*
 * These are not being advertised because the interfaces are non-standard.
 * There are versions by linux, aix, qnx, sun, etc. Our versions are used
 * internally to provide thread safety; they mostly resemble qnx.
 */
void sethostent_r(FILE **);
struct hostent	*netbsd_gethostent_r(FILE *, struct hostent *, char *, size_t, int *);
void endhostent_r(FILE **);

/*
 * The following are internal API's and are used only for testing.
 */
struct getnamaddr {
	struct hostent *hp;
	char *buf;
	size_t buflen;
	int *he;
};

/* /etc/hosts lookup */
int _hf_gethtbyaddr(void *, void *, va_list);
int _hf_gethtbyname(void *, void *, va_list);

#ifdef YP
/* NIS lookup */
int _yp_gethtbyaddr(void *, void *, va_list);
int _yp_gethtbyname(void *, void *, va_list);
#endif

#define HENT_ARRAY(dst, anum, ptr, len) \
	do { \
		size_t _len = (anum + 1) * sizeof(*dst); \
		if (_len > len) \
			goto nospc; \
		dst = (void *)ptr; \
		ptr += _len; \
		len -= _len; \
	} while (/*CONSTCOND*/0)

#define HENT_COPY(dst, src, slen, ptr, len) \
	do { \
		if ((size_t)slen > len) \
			goto nospc; \
		memcpy(ptr, src, (size_t)slen); \
		dst = ptr; \
		ptr += slen; \
		len -= slen; \
	} while (/* CONSTCOND */0)

#define HENT_SCOPY(dst, src, ptr, len) \
	do { \
		size_t _len = strlen(src) + 1; \
		HENT_COPY(dst, src, _len, ptr, len); \
	} while (/* CONSTCOND */0)

#endif /* _DNS_NET_HOSTENT_H */
```