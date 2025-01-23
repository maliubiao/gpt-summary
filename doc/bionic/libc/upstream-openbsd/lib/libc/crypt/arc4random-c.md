Response:
Let's break down the thought process for answering the request about `arc4random.c`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided `arc4random.c` code within the context of Android's Bionic library. The request specifically asks for:

* Functionality description.
* Relationship to Android.
* Detailed explanation of libc functions.
* Dynamic linker aspects (if any).
* Logical inference (with examples).
* Common usage errors.
* How it's reached from Android framework/NDK (with Frida example).

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, paying attention to key elements:

* **Includes:**  `<fcntl.h>`, `<limits.h>`, `<signal.h>`, `<stdint.h>`, `<stdlib.h>`, `<string.h>`, `<unistd.h>`, `<sys/types.h>`, `<sys/time.h>`, `"chacha_private.h"`, `"arc4random.h"`. These give clues about the dependencies and the purpose. We can see standard libc headers and custom headers likely related to the ChaCha algorithm.
* **Copyright:**  Indicates the origin from OpenBSD. This is a crucial piece of information for understanding its place in Android.
* **Function Names:** `arc4random`, `arc4random_buf`, `_rs_init`, `_rs_stir`, `_rs_rekey`, `_rs_random_buf`, `_rs_random_u32`, `_rs_stir_if_needed`. These reveal the core functionalities related to random number generation.
* **Data Structures:** `struct _rs`, `struct _rsx`. These hold the state of the random number generator. The comments about `MAP_INHERIT_ZERO` are important.
* **Algorithm Name:** "ChaCha based random number generator". This tells us the underlying cryptographic algorithm.
* **`getentropy`:** A function for obtaining high-quality randomness from the operating system.
* **`explicit_bzero`:** A function for securely zeroing out memory.
* **Macros:** `KEYSZ`, `IVSZ`, `BLOCKSZ`, `RSBUFSZ`, `REKEY_BASE`, `minimum`, `inline`. These define constants and optimization hints.
* **Locking:** `_ARC4_LOCK()`, `_ARC4_UNLOCK()`. This indicates thread safety considerations.
* **Weak Symbols:** `DEF_WEAK`. This suggests potential overriding or conditional linking.

**3. Functionality Extraction and High-Level Description:**

Based on the function names and code structure, the core functionalities are:

* **Initialization (`_rs_init`, `_rs_stir`):** Setting up the random number generator with initial seed material. The use of `getentropy` is significant.
* **Generating Random Numbers (`arc4random`, `arc4random_buf`, `_rs_random_u32`, `_rs_random_buf`):**  The primary purpose of the code. It uses the ChaCha algorithm to generate a keystream.
* **Rekeying (`_rs_rekey`, `_rs_stir_if_needed`):** Periodically refreshing the internal state to maintain security and prevent prediction.
* **Fork Handling (`_rs_allocate`, `_rs_forkdetect`):** Addressing the challenges of randomness after a `fork()` system call.

**4. Connecting to Android:**

The key insight here is the "bionic" path in the request. This immediately tells us that this code *is* part of Android's standard C library. The OpenBSD origin is also important context. Android often incorporates code from other open-source projects.

**5. Detailed Explanation of libc Functions:**

For each internal function (`_rs_init`, etc.), the explanation should focus on *what* it does and *how* it achieves it. This involves:

* Describing the purpose of the function.
* Explaining the main steps involved (e.g., key setup, IV setup, encryption).
* Mentioning relevant data structures and parameters.

**6. Dynamic Linker Aspects:**

The code itself doesn't directly manipulate the dynamic linker. However, the *fact* that it's part of `libc.so` is the critical link. The explanation should cover:

* The concept of shared libraries (`.so`).
* How `libc.so` is loaded by the dynamic linker.
* How applications link against `libc.so`.
* A simplified `.so` layout example.
* The symbol resolution process.

**7. Logical Inference and Examples:**

This involves demonstrating how the functions work with concrete examples:

* **Initialization:**  Show how the initial seed is used to set up the ChaCha state.
* **Random Number Generation:**  Illustrate how the keystream is generated and used to produce random bytes.
* **Rekeying:** Explain why and how rekeying enhances security.

**8. Common Usage Errors:**

Think about how developers might misuse these functions:

* **Not seeding properly (though `arc4random` handles this internally).**
* **Assuming perfect randomness for cryptographic keys (though `arc4random` is designed for crypto).**
* **Performance issues if called too frequently (less of a concern with modern implementations).**

**9. Android Framework/NDK and Frida Hooking:**

This requires tracing the path from a high-level Android component to the `arc4random` call:

* **Framework Example:**  Start with something like `SecureRandom` in Java, then trace down through JNI calls to native code. Mentioning services like `entropySource` is beneficial.
* **NDK Example:** Show a simple C/C++ program using `arc4random.h`.
* **Frida Hooking:**  Provide concrete Frida code to intercept calls to `arc4random` and examine arguments/return values.

**10. Structuring the Answer:**

Organize the information logically using headings and subheadings to make it easy to read and understand. Use clear and concise language. Provide code snippets and diagrams where appropriate.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the dynamic linker is heavily involved in `_rs_allocate`.
* **Correction:**  `_rs_allocate` handles memory allocation, potentially with `mmap` and `MAP_INHERIT_ZERO`. The dynamic linker's involvement is primarily in loading `libc.so` itself.
* **Initial thought:** Focus heavily on the cryptographic details of ChaCha.
* **Correction:** While important, keep the ChaCha explanation at a high level unless the request specifically asks for deep crypto analysis. Focus on the *purpose* within `arc4random`.
* **Initial thought:** Assume the reader has a deep understanding of Android internals.
* **Correction:** Explain concepts like JNI, NDK, and dynamic linking clearly, assuming a broader audience.

By following these steps and iteratively refining the approach, you can construct a comprehensive and accurate answer to the complex request.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/crypt/arc4random.c` 这个文件。

**1. 功能列举**

`arc4random.c` 实现了以下主要功能：

* **提供高质量的伪随机数生成:**  这是其核心功能。它使用 ChaCha 流密码作为底层算法来生成随机字节流。
* **自动初始化和重新播种 (reseed):**  代码会自动获取系统熵源（通过 `getentropy`）来初始化随机数生成器，并定期或在必要时重新播种以保持随机性。
* **线程安全:**  通过 `_ARC4_LOCK()` 和 `_ARC4_UNLOCK()` 宏（在 `arc4random.h` 中定义），确保在多线程环境中使用时的安全性。
* **防止分叉 (fork) 后的状态重复:**  使用了 `MAP_INHERIT_ZERO` 标志，使得在 `fork()` 之后，子进程的随机数生成器状态会被清零，避免父子进程生成相同的随机数序列。
* **提供生成指定长度随机字节的接口:**  `arc4random_buf()` 函数允许用户获取指定大小的随机字节数组。
* **提供生成单个 32 位无符号整数的接口:**  `arc4random()` 函数返回一个 32 位的随机无符号整数。

**2. 与 Android 功能的关系及举例**

`arc4random.c` 是 Android Bionic libc 的一部分，这意味着它是 Android 系统中所有用户空间程序都可以使用的基础库。它的功能与 Android 的多个方面密切相关：

* **安全性:** Android 系统和应用程序的许多安全功能依赖于高质量的随机数，例如：
    * **生成加密密钥:**  例如，用于 HTTPS 连接、VPN 连接、文件加密等的密钥。
    * **生成初始化向量 (IVs):**  与密钥一起用于加密算法。
    * **生成 salts:**  用于密码哈希，增加破解难度。
    * **生成令牌 (tokens) 和会话 ID:**  用于身份验证和授权。
    * **生成随机文件名或路径:**  用于创建临时文件等。
    * **生成 ASLR (地址空间布局随机化) 的随机偏移:**  提高抵抗内存攻击的能力。
* **应用程序开发:** Android 应用程序开发者可以使用 `arc4random()` 和 `arc4random_buf()` 来实现各种需要随机性的功能，例如：
    * **游戏开发:**  生成随机的游戏事件、敌人行为、掉落物品等。
    * **数据处理:**  随机抽样、洗牌等。
    * **用户界面:**  实现随机动画效果等。
    * **网络编程:**  生成随机端口号（虽然不推荐直接使用）。

**举例说明:**

* **Java SecureRandom:**  Android Framework 中的 `java.security.SecureRandom` 类通常会委托给底层的 `arc4random` 来获取随机数。当你使用 Java 代码生成一个安全的随机数时，最终会调用到这里的 C 代码。
* **NDK 开发:** 使用 C 或 C++ 开发 Android 原生库时，可以直接包含 `<stdlib.h>` 并调用 `arc4random()` 或 `arc4random_buf()`。

**3. libc 函数的功能实现**

接下来，我们详细解释一下 `arc4random.c` 中关键的 libc 函数的实现：

* **`getentropy(rnd, sizeof rnd)`:**
    * **功能:**  这是一个从操作系统获取高质量随机数据的系统调用。它的目的是从各种硬件和软件源收集熵，例如 CPU 时间抖动、设备驱动程序的随机事件等。
    * **实现:**  `getentropy` 的具体实现位于 Android 内核中。它会尝试从各种熵源收集足够的随机性来填充提供的缓冲区。如果系统没有足够的熵，`getentropy` 可能会阻塞，直到收集到足够的熵为止。这是获取安全随机数的首选方法。
* **`memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf))` 和 `explicit_bzero(rnd, sizeof(rnd))`:**
    * **功能:**  这两个函数都用于将内存块设置为零。`memset` 是标准的 C 库函数，而 `explicit_bzero` 旨在防止编译器优化掉敏感数据的清零操作，以提高安全性。
    * **实现:**  `memset` 通常由编译器或 libc 提供高效的实现，通常使用汇编指令快速填充内存。`explicit_bzero` 的实现方式可能类似，但它被设计为不被优化，确保数据确实被擦除。
* **`memcpy(buf, keystream, m)`:**
    * **功能:**  将内存块从一个位置复制到另一个位置。
    * **实现:**  `memcpy` 是一个经过高度优化的标准 C 库函数，通常使用汇编指令进行高效的内存复制。
* **`abort()`:**
    * **功能:**  导致程序立即异常终止。
    * **实现:**  `abort()` 通常会触发一个 `SIGABRT` 信号，操作系统会捕获该信号并终止进程，可能会生成一个 core dump 文件用于调试。
* **`chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8)` 和 `chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ)`:**
    * **功能:**  这两个函数是 `chacha_private.h` 中定义的，用于初始化 ChaCha 流密码的上下文。`chacha_keysetup` 设置密钥，`chacha_ivsetup` 设置初始化向量 (IV)。
    * **实现:**  这些函数会根据提供的密钥和 IV 对 ChaCha 的内部状态进行初始化，包括填充状态数组。ChaCha 是一种基于 ARX (加法、旋转、异或) 操作的流密码。
* **`chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf, rsx->rs_buf, sizeof(rsx->rs_buf))` 和 `chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz, (uint8_t *)&rekey_fuzz, sizeof(rekey_fuzz))`:**
    * **功能:**  这些函数也是 `chacha_private.h` 中定义的，用于执行 ChaCha 流密码的加密操作。由于 ChaCha 是流密码，其加密过程实际上是生成密钥流 (keystream)，然后与明文进行异或操作。在这里，`arc4random` 将密钥流生成到 `rsx->rs_buf` 中，或者用于生成一个随机的重新播种间隔。
    * **实现:**  这些函数会执行 ChaCha 算法的核心循环，对内部状态进行多轮的 ARX 操作，生成伪随机的字节。
* **`minimum(a, b)`:**
    * **功能:**  返回两个值中较小的一个。
    * **实现:**  这是一个简单的宏定义，使用三元运算符实现。
* **`_ARC4_LOCK()` 和 `_ARC4_UNLOCK()`:**
    * **功能:**  用于实现互斥锁，保护 `arc4random` 的内部状态，防止多线程并发访问时出现竞争条件。
    * **实现:**  这些宏通常在 `arc4random.h` 中定义，并映射到平台相关的互斥锁实现，例如 pthreads 库中的 `pthread_mutex_lock()` 和 `pthread_mutex_unlock()`。
* **`DEF_WEAK(arc4random)` 和 `DEF_WEAK(arc4random_buf)`:**
    * **功能:**  这些宏用于声明弱符号。弱符号允许在链接时被其他更强的同名符号覆盖。
    * **实现:**  `DEF_WEAK` 的具体实现依赖于编译器和链接器。它通常会使用特定的编译器属性（例如 GCC 的 `__attribute__((weak))`) 来标记符号为弱符号。这允许其他库或应用程序提供自己的 `arc4random` 实现，例如，在某些受限的环境中，可能需要使用不同的随机数生成器。

**4. 涉及 dynamic linker 的功能**

`arc4random.c` 本身的代码并没有直接涉及动态链接器的操作。但是，作为 `libc.so` 的一部分，它与动态链接器有着根本的联系：

* **作为共享库 (`.so`) 被加载:**  `arc4random.c` 编译后的代码最终会被链接到 `libc.so` 共享库中。当 Android 应用程序启动时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载 `libc.so` 到进程的地址空间。
* **符号解析:**  当应用程序调用 `arc4random()` 或 `arc4random_buf()` 时，动态链接器会负责解析这些符号，找到 `libc.so` 中对应的函数地址并跳转执行。

**so 布局样本:**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text          # 代码段
        ...
        arc4random:  # arc4random 函数的代码
            ...
        arc4random_buf: # arc4random_buf 函数的代码
            ...
        _rs_init:
            ...
        ...
    .data          # 已初始化数据段
        ...
        rs:          # 全局变量 rs 的存储空间
        rsx:         # 全局变量 rsx 的存储空间
        ...
    .bss           # 未初始化数据段
        ...
    .dynsym        # 动态符号表 (包含 arc4random 等符号)
    .dynstr        # 动态字符串表 (包含符号名称)
    .rel.plt       # PLT 重定位表
    ...
```

**链接的处理过程:**

1. **编译时:**  当编译一个使用 `arc4random` 的程序时，编译器会生成对 `arc4random` 的外部符号引用。
2. **链接时:**  静态链接器（如果进行静态链接，通常不用于 Android 的应用程序）或动态链接器会在链接时处理这些外部符号引用。对于动态链接，链接器会在生成的可执行文件中记录对 `libc.so` 和 `arc4random` 符号的依赖。
3. **运行时:**
    * 当应用程序启动时，操作系统会加载程序的可执行文件。
    * 动态链接器被启动。
    * 动态链接器读取可执行文件的头部信息，找到依赖的共享库列表，其中包含 `libc.so`。
    * 动态链接器加载 `libc.so` 到进程的地址空间。
    * 动态链接器遍历可执行文件中的重定位表，找到对 `arc4random` 等符号的引用。
    * 动态链接器在 `libc.so` 的动态符号表中查找 `arc4random` 的地址。
    * 动态链接器将找到的地址填入可执行文件的 PLT (Procedure Linkage Table) 或 GOT (Global Offset Table) 中，以便程序可以正确调用 `arc4random`。

**5. 逻辑推理与假设输入输出**

让我们分析一下 `_rs_stir` 函数的逻辑：

**假设输入:**  系统熵源提供了一些随机字节。

**逻辑推理:**

1. `getentropy(rnd, sizeof rnd)` 被调用，假设成功获取了 `KEYSZ + IVSZ` (32 + 8 = 40) 字节的随机数据到 `rnd` 缓冲区。
2. 如果 `rs` 为空（第一次调用），则调用 `_rs_init(rnd, sizeof(rnd))`。
   * `chacha_keysetup` 使用 `rnd` 的前 32 字节作为密钥初始化 `rsx->rs_chacha`。
   * `chacha_ivsetup` 使用 `rnd` 的后 8 字节作为 IV 初始化 `rsx->rs_chacha`。
3. 如果 `rs` 不为空（后续调用），则调用 `_rs_rekey(rnd, sizeof(rnd))`。
   * `chacha_encrypt_bytes` 使用当前的 `rsx->rs_chacha` 生成一个密钥流覆盖 `rsx->rs_buf`。
   * `rsx->rs_buf` 的前 40 字节与 `rnd` 中的随机数据进行异或运算，混合新的熵。
   * `_rs_init` 再次使用混合后的 `rsx->rs_buf` 的前 40 字节重新初始化 `rsx->rs_chacha`，实现“立即重新初始化”以增强抗回溯性。
4. `explicit_bzero(rnd, sizeof(rnd))` 清零 `rnd` 缓冲区，防止敏感数据残留。
5. `memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf))` 清零 `rsx->rs_buf`，除非定义了 `KEYSTREAM_ONLY`。
6. `chacha_encrypt_bytes` 使用当前的 `rsx->rs_chacha` 生成一个 4 字节的随机数到 `rekey_fuzz`。
7. `rs->rs_count` 被设置为 `REKEY_BASE + (rekey_fuzz % REKEY_BASE)`，这意味着下一次重新播种将在生成大约 1MB 到 2MB 随机数据之后发生（假设 `REKEY_BASE` 为 1MB）。

**假设输出:**  `_rs_stir` 函数的主要输出是更新了 `rsx->rs_chacha` 的内部状态和 `rs->rs_count`，为后续的随机数生成做准备。

**6. 用户或编程常见的使用错误**

* **错误地假设 `arc4random` 是完全不可预测的:** 虽然 `arc4random` 使用了强大的加密算法，但它仍然是一个伪随机数生成器。如果初始种子泄露或者状态被破坏，其输出可能会被预测。
* **在 `fork()` 之后没有意识到状态可能重复:**  在没有正确处理的情况下，`fork()` 后的父子进程会共享相同的随机数生成器状态。虽然 `arc4random` 尝试通过 `MAP_INHERIT_ZERO` 来缓解这个问题，但依赖于这一点可能不够安全，尤其是在需要高度安全性的场景中。建议在 `fork()` 后显式地重新播种子进程的随机数生成器。
* **过度依赖随机数进行安全关键操作而不进行其他安全措施:**  随机数生成只是安全系统的一部分。应该结合其他安全措施，例如加密协议、身份验证机制等。
* **在性能敏感的应用中过度调用 `arc4random`:**  虽然 `arc4random` 相对高效，但在极高频率的调用下也可能成为性能瓶颈。如果只需要一些简单的随机性，可以考虑使用更轻量级的 PRNG。
* **错误地假设 `arc4random` 在所有平台上都以相同的方式工作:**  尽管 Android 的 `arc4random` 基于 OpenBSD 的实现，但在其他系统上的行为可能有所不同。如果编写跨平台代码，需要注意这一点。

**7. Android framework 或 ndk 如何到达这里，Frida hook 示例**

**Android Framework 到 `arc4random` 的路径示例:**

1. **Java 代码:**  在 Android Framework 中，例如需要生成一个安全的随机数时，可能会使用 `java.security.SecureRandom` 类。
   ```java
   SecureRandom secureRandom = new SecureRandom();
   byte[] randomBytes = new byte[16];
   secureRandom.nextBytes(randomBytes);
   ```
2. **JNI 调用:** `SecureRandom` 的某些实现会通过 JNI (Java Native Interface) 调用到底层的 Native 代码。
3. **Native 代码 (例如，`libjavacrypto.so`):**  在 `libjavacrypto.so` 中，可能会调用 Bionic libc 提供的 `arc4random_buf` 或 `arc4random`。具体的实现细节可能因 Android 版本和使用的 `SecureRandom` 提供程序而异。

**NDK 到 `arc4random` 的路径示例:**

1. **C/C++ 代码:**  在 NDK 开发中，可以直接包含 `<stdlib.h>` 并调用 `arc4random` 或 `arc4random_buf`。
   ```c
   #include <stdlib.h>
   #include <stdio.h>

   int main() {
       unsigned int random_value = arc4random();
       printf("Random value: %u\n", random_value);
       return 0;
   }
   ```
2. **编译和链接:**  使用 NDK 工具链编译该代码时，链接器会将对 `arc4random` 的引用链接到 `libc.so` 中。
3. **运行时:**  当应用程序启动并执行到调用 `arc4random` 的代码时，会通过动态链接器找到 `libc.so` 中 `arc4random` 的实现并执行。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `arc4random` 的示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python frida_arc4random.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "arc4random"), {
        onEnter: function (args) {
            console.log("[*] arc4random() called");
        },
        onLeave: function (retval) {
            console.log("[*] arc4random() returned: " + retval);
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "arc4random_buf"), {
        onEnter: function (args) {
            var buf = args[0];
            var size = args[1].toInt();
            console.log("[*] arc4random_buf(buf=" + buf + ", size=" + size + ") called");
        },
        onLeave: function (retval) {
            console.log("[*] arc4random_buf returned: " + retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Hooking, press Ctrl+C to stop...")
    sys.stdin.read()

    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 确保已安装 Frida 和 Python 的 Frida 绑定。
2. 找到你想要 hook 的进程的名称或 PID。
3. 运行脚本：`python frida_arc4random.py <进程名称或PID>`
4. 当目标进程调用 `arc4random` 或 `arc4random_buf` 时，Frida 会打印出相应的日志信息，包括函数调用和返回值。

这个 Frida 脚本会拦截对 `libc.so` 中 `arc4random` 和 `arc4random_buf` 函数的调用，并在函数进入和退出时打印日志信息，帮助你观察这些函数的调用时机和参数。

希望以上详细的解释能够帮助你理解 `bionic/libc/upstream-openbsd/lib/libc/crypt/arc4random.c` 的功能、在 Android 中的作用以及如何进行调试。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/crypt/arc4random.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: arc4random.c,v 1.58 2022/07/31 13:41:45 tb Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ChaCha based random number generator for OpenBSD.
 */

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#define KEYSTREAM_ONLY
#include "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#if defined(__GNUC__) || defined(_MSC_VER)
#define inline __inline
#else				/* __GNUC__ || _MSC_VER */
#define inline
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
static struct _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_count;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
static struct _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

static inline int _rs_allocate(struct _rs **, struct _rsx **);
static inline void _rs_forkdetect(void);
#include "arc4random.h"

static inline void _rs_rekey(u_char *dat, size_t datlen);

static inline void
_rs_init(u_char *buf, size_t n)
{
	if (n < KEYSZ + IVSZ)
		return;

	if (rs == NULL) {
		if (_rs_allocate(&rs, &rsx) == -1)
			abort();
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

static void
_rs_stir(void)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	if (getentropy(rnd, sizeof rnd) == -1)
		_getentropy_fail();

	if (!rs)
		_rs_init(rnd, sizeof(rnd));
	else
		_rs_rekey(rnd, sizeof(rnd));
	explicit_bzero(rnd, sizeof(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, sizeof(rekey_fuzz));
	rs->rs_count = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

static inline void
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	if (!rs || rs->rs_count <= len)
		_rs_stir();
	if (rs->rs_count <= len)
		rs->rs_count = 0;
	else
		rs->rs_count -= len;
}

static inline void
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, sizeof(rsx->rs_buf));
	/* mix in optional user provided data */
	if (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		for (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = sizeof(rsx->rs_buf) - KEYSZ - IVSZ;
}

static inline void
_rs_random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	while (n > 0) {
		if (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + sizeof(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		if (rs->rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}

static inline void
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(sizeof(*val));
	if (rs->rs_have < sizeof(*val))
		_rs_rekey(NULL, 0);
	keystream = rsx->rs_buf + sizeof(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, sizeof(*val));
	memset(keystream, 0, sizeof(*val));
	rs->rs_have -= sizeof(*val);
}

uint32_t
arc4random(void)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	return val;
}
DEF_WEAK(arc4random);

void
arc4random_buf(void *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
```