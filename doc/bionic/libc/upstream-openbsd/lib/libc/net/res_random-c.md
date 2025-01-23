Response:
Let's break down the thought process for analyzing the `res_random.c` code. The goal is to fulfill the user's request, covering functionality, Android relevance, implementation details, dynamic linking, error scenarios, and how Android utilizes this code, including Frida hooking.

**1. Initial Understanding and Keyword Extraction:**

First, read through the code and the accompanying comments. Identify the core purpose: generating pseudo-random 16-bit numbers, primarily for DNS transaction IDs. Key terms emerge: `res_randomid`, `seed`, `generator`, `LCG`, `Luby-Rackoff`, `permutation`, `reseed`.

**2. High-Level Functionality Breakdown:**

Based on the comments and code structure, outline the major steps involved in generating a random ID:

*   **Initialization (`res_initid`):**  Sets up the internal state (seeds, generator, LCG parameters). This happens infrequently.
*   **Linear Congruential Generator (LCG):** Generates a sequence of numbers based on a formula. This is the core engine.
*   **Modular Exponentiation (`pmod`):** Used to calculate powers modulo a number, essential for the generator.
*   **Permutation (`permute15`):**  Applies a Luby-Rackoff block cipher to the LCG output for better randomness.
*   **Combining and Output:**  XORs the seed with the permuted LCG output and adds an MSB toggle.
*   **Reseeding:**  Periodically re-initializes to prevent predictable sequences.

**3. Detailed Implementation Analysis (Function by Function):**

Go through each function and explain its purpose and how it achieves it:

*   **`pmod`:** Explain the modular exponentiation algorithm (repeated squaring).
*   **`permute15`:** Describe the Luby-Rackoff structure, the use of PRF tables, and how the left and right parts are processed in each round. Highlight the role of `ru_prf`.
*   **`res_initid`:**  Explain each step:
    *   Random initial value for LCG (`ru_x`).
    *   Generating random seeds (`ru_seed`, `ru_seed2`).
    *   Choosing LCG parameters (`ru_a`, `ru_b`) ensuring `gcd(ru_b, RU_M) == 1`.
    *   Selecting a generator (`ru_g`) using `pmod` and ensuring `gcd(j, RU_N-1) == 1`. Explain the purpose of the primality check.
    *   Initializing the PRF table (`ru_prf`) with random data.
    *   Setting the reseed timer and toggling the MSB.
*   **`__res_randomid`:** Describe the main logic:
    *   Checking for reseeding conditions.
    *   Updating the LCG state.
    *   Combining the seed and the generator output.
    *   Permuting the result.
    *   Adding the MSB.
    *   Thread safety using a mutex.

**4. Android Relevance and Examples:**

Think about how DNS resolution is used in Android. Network requests are common. The transaction ID is crucial for matching requests and responses. Provide a concrete example of an app making a network request that triggers DNS resolution.

**5. Dynamic Linking:**

Identify the relevant library (`libc.so`). Explain the purpose of dynamic linking and how the resolver functions in `libc.so` are used by applications. Provide a simplified `libc.so` layout example, showing the presence of resolver functions. Briefly describe the linking process (symbol lookup, relocation).

**6. Assumptions, Inputs, and Outputs:**

Focus on the core random ID generation function (`__res_randomid`). What are the conceptual inputs (current state, time)?  What is the output (a 16-bit random number)?  Provide a simple hypothetical scenario.

**7. Common Usage Errors:**

Think about how a programmer might misuse or misunderstand this functionality. The main point is that they *shouldn't* be directly calling these internal functions. Explain that the resolver library handles this automatically. Mention the potential problems of trying to manage transaction IDs manually.

**8. Android Framework/NDK Flow and Frida Hooking:**

This requires understanding the Android networking stack. Trace the path from an app's network request to the underlying DNS resolver.

*   **App Level:** `java.net.URL`, `OkHttp`, etc.
*   **Framework Level:**  `android.net.ConnectivityManager`, `DnsResolver`.
*   **NDK Level:**  `getaddrinfo`.
*   **Bionic/libc:** `res_randomid`.

Create a Frida script that targets `__res_randomid` in `libc.so`. Show how to print the return value and potentially the internal state if you wanted to dig deeper (though this example keeps it simple).

**9. Language and Formatting:**

Ensure the response is in Chinese as requested. Use clear headings, bullet points, and code formatting to make the information easy to read and understand.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:** Maybe focus heavily on the math of the LCG and permutation.
*   **Correction:** While explaining the mechanisms is important, prioritize the *purpose* and *use* of the code within Android. Avoid getting lost in excessive mathematical detail unless it's directly relevant to understanding the function.
*   **Initial thought:** Explain all possible dynamic linking scenarios.
*   **Correction:** Keep the dynamic linking explanation focused on the specific context of `libc.so` and the resolver functions. A general explanation of dynamic linking is less useful here.
*   **Initial thought:** Provide very complex Frida examples.
*   **Correction:** Start with a simple and understandable Frida hook to demonstrate the basic concept. More complex examples can be confusing for someone just trying to understand how to interact with this code.

By following these steps and iteratively refining the explanation, you can construct a comprehensive and accurate answer that addresses all aspects of the user's request.
这是一个关于 Android Bionic 中 `bionic/libc/upstream-openbsd/lib/libc/net/res_random.c` 源代码文件的分析。这个文件包含了生成用于 DNS 查询的随机 ID 的函数。

**功能列举:**

1. **生成伪随机的 16 位整数:**  核心功能是生成看似随机的、用于标识 DNS 查询事务的 16 位 ID。
2. **防止 ID 重复:**  通过使用线性同余发生器 (LCG) 和 Luby-Rackoff 分组密码进行置换，并结合周期性地重新播种 (reseeding) 和切换最高有效位 (MSB)，来降低 ID 重复的概率。
3. **线程安全:** 使用互斥锁 (`_THREAD_PRIVATE_MUTEX`) 来保护内部状态，确保在多线程环境下的正确性。
4. **周期性重新播种:** 在一定时间间隔后 (`RU_OUT`) 或当生成的 ID 数量达到上限 (`RU_MAX`) 时，重新初始化生成器的状态，增加随机性。
5. **与 `res_init` 函数集成:**  这个文件中的函数通常由 DNS 解析库的初始化函数（例如 `res_init`）间接调用。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 设备进行 DNS 查询的功能。当 Android 应用需要解析域名时，系统底层的 DNS 解析器会生成一个唯一的事务 ID 来标识这个查询。这个 ID 被包含在 DNS 查询报文中，当收到 DNS 服务器的响应时，系统可以通过这个 ID 将响应匹配回对应的查询请求。

**举例说明:**

假设一个 Android 应用需要访问 `www.example.com`。

1. 应用发起网络请求，需要解析域名 `www.example.com`。
2. Android 系统调用底层的 DNS 解析库。
3. DNS 解析库需要构造一个 DNS 查询报文。
4. 为了标识这个查询，DNS 解析库会调用 `__res_randomid()` 函数来生成一个随机的 16 位事务 ID。
5. 生成的 ID 被填充到 DNS 查询报文的 "ID" 字段中。
6. DNS 查询报文被发送到 DNS 服务器。
7. DNS 服务器处理查询并返回一个响应报文，其中包含相同的事务 ID。
8. Android 系统接收到响应报文，并根据报文中的事务 ID 找到对应的查询请求，并将解析结果返回给应用。

**libc 函数的功能实现详细解释:**

1. **`pmod(u_int16_t gen, u_int16_t exp, u_int16_t mod)`:**
    *   **功能:**  计算 `gen` 的 `exp` 次方模 `mod` 的结果，即 `(gen ^ exp) % mod`。这是一个高效的模幂运算函数。
    *   **实现:** 使用平方乘法算法。该算法通过迭代的方式，根据指数 `exp` 的二进制表示，逐步计算结果。
        *   初始化 `s = 1`, `t = gen`, `u = exp`。
        *   当 `u` 大于 0 时循环：
            *   如果 `u` 的最低位是 1，则 `s = (s * t) % mod`。
            *   将 `u` 右移一位 (`u >>= 1`)。
            *   计算 `t` 的平方模 `mod`，即 `t = (t * t) % mod`。
        *   返回 `s`。
    *   **假设输入与输出:**  例如 `pmod(2, 10, 100)` 将返回 `24` (因为 2^10 = 1024, 1024 % 100 = 24)。

2. **`permute15(u_int in)`:**
    *   **功能:** 对输入的 15 位整数 `in` 进行基于 Luby-Rackoff 分组密码的置换。
    *   **实现:**
        *   如果 PRF 表 (`ru_prf`) 未初始化，则直接返回输入。
        *   将输入的 15 位数分成左右两部分：左边 7 位，右边 8 位。
        *   执行 `RU_ROUNDS` (默认为 11) 轮置换。每一轮都交换左右两部分，并使用 PRF 表进行非线性变换。
        *   奇数轮使用 `prf8` 表（8 位输入到 7 位输出），偶数轮使用 `prf7` 表（7 位输入到 8 位输出）。
        *   每一轮的变换公式类似于 Feistel 网络的结构：`tmp = PRF(right) ^ left; left = right; right = tmp;`。
        *   最后将左右两部分合并成 15 位数返回。
    *   **假设输入与输出:**  假设 `ru_prf` 已初始化，输入 `0x1234` (二进制 `0001001000110100`)，经过多轮置换后，输出将是一个看起来与输入没有明显关系的 15 位整数。具体的输出值取决于 `ru_prf` 的内容。

3. **`res_initid(void)`:**
    *   **功能:** 初始化随机 ID 生成器的状态。
    *   **实现:**
        *   使用 `arc4random_uniform` 生成一个 0 到 `RU_M - 1` 之间的随机数作为线性同余发生器的初始值 `ru_x`。
        *   使用 `arc4random` 生成 30 位随机数，并提取低 15 位作为种子 `ru_seed` 和 `ru_seed2`。
        *   确定线性同余发生器的参数 `ru_a` 和 `ru_b`。`ru_b` 是一个奇数，`ru_a` 的计算涉及到模幂运算。
        *   选择一个新的生成器 `ru_g`。通过选择一个与 `RU_N - 1` 互质的随机数 `j`，然后计算 `RU_GEN` 的 `j` 次方模 `RU_N` 得到。这样可以确保 `ru_g` 也是模 `RU_N` 的一个生成元。
        *   重置计数器 `ru_counter` 为 0。
        *   如果 PRF 表 `ru_prf` 未分配内存，则分配内存并使用 `arc4random_buf` 填充随机数据。
        *   记录当前的单调时间，并加上 `RU_OUT` 作为下次重新播种的时间 `ru_reseed`。
        *   切换最高有效位 `ru_msb`，用于生成两个不同的随机数周期。

4. **`__res_randomid(void)`:**
    *   **功能:** 生成一个新的随机 ID。
    *   **实现:**
        *   获取当前的单调时间和进程 ID。
        *   使用互斥锁保护内部状态。
        *   检查是否需要重新播种：如果生成的 ID 数量超过 `RU_MAX`，或者当前时间超过了 `ru_reseed`，或者进程 ID 发生了变化，则调用 `res_initid()` 重新初始化。
        *   使用线性同余发生器更新 `ru_x`: `ru_x = (ru_a * ru_x + ru_b) % RU_M;`
        *   递增计数器 `ru_counter`。
        *   计算中间值：`pmod(ru_g, ru_seed2 + ru_x, RU_N)`。
        *   将种子 `ru_seed` 与中间值进行异或。
        *   对异或结果进行 15 位置换 `permute15()`。
        *   将置换后的结果与最高有效位 `ru_msb` 进行或运算，得到最终的随机 ID。
        *   释放互斥锁。
        *   返回生成的随机 ID。

**涉及 dynamic linker 的功能:**

这个文件本身不直接涉及 dynamic linker 的功能。它的代码被编译到 `libc.so` 动态链接库中。应用程序在运行时，如果调用了需要进行 DNS 解析的函数（例如 `getaddrinfo`），`libc.so` 中的 DNS 解析相关代码会被执行，进而调用到 `__res_randomid` 来生成随机 ID。

**so 布局样本 (简化):**

```
libc.so:
    ...
    .text:
        ...
        res_initid:  <res_initid 函数的代码>
        __res_randomid: <__res_randomid 函数的代码>
        pmod:        <pmod 函数的代码>
        permute15:   <permute15 函数的代码>
        ...
        getaddrinfo: <getaddrinfo 函数的代码>
        ...
    .data:
        ...
        ru_x:        <全局变量 ru_x>
        ru_seed:     <全局变量 ru_seed>
        ...
        ru_prf:      <全局变量 ru_prf>
        ...
    ...
```

**链接的处理过程:**

1. 当应用程序调用 `getaddrinfo` 时，该函数位于 `libc.so` 中。
2. `getaddrinfo` 的实现会涉及到 DNS 查询。
3. 在构造 DNS 查询报文的过程中，`getaddrinfo` 会间接调用 `__res_randomid` 来生成事务 ID。
4. dynamic linker 在加载 `libc.so` 时，会解析 `__res_randomid` 等符号的地址，并将应用程序中的调用指向 `libc.so` 中对应的代码。

**用户或编程常见的使用错误:**

用户或开发者通常不会直接调用 `__res_randomid` 或 `res_initid`。这些是 libc 内部使用的函数。尝试直接调用可能会导致未定义的行为或崩溃，因为这些函数依赖于特定的内部状态。

**假设的错误使用场景:**

假设开发者尝试直接调用 `__res_randomid` 并将其生成的 ID 用于其他目的，可能会遇到以下问题：

1. **依赖内部状态:** `__res_randomid` 依赖于 `res_initid` 的初始化，如果直接调用而没有正确的初始化，可能会得到不可预测的结果。
2. **线程安全问题:**  如果开发者在没有正确加锁的情况下直接在多线程环境中使用，可能会导致竞争条件。
3. **误解用途:**  这个函数专门用于生成 DNS 事务 ID，其随机性特征是为这个特定用途设计的，可能不适合其他需要更高强度或不同分布的随机数的场景。

**Android framework 或 ndk 如何一步步的到达这里:**

1. **Android Framework (Java 层):**
    *   应用程序发起网络请求，例如使用 `java.net.URL` 或 `OkHttp` 等库。
    *   这些库最终会调用到 Android Framework 层的网络相关服务，例如 `android.net.ConnectivityManager`。
    *   `ConnectivityManager` 或其底层的网络栈在需要解析域名时，会使用 `android.net.DnsResolver` 或类似组件。

2. **NDK (Native 层):**
    *   Native 代码可以使用标准的 C 库函数进行网络操作，例如 `getaddrinfo`。

3. **Bionic/libc:**
    *   无论是 Framework 还是 NDK 发起的 DNS 查询，最终都会调用到 Bionic 的 `libc.so` 中的 DNS 解析相关函数，例如 `getaddrinfo`。
    *   `getaddrinfo` 函数的内部实现会调用到与 DNS 查询相关的函数，这些函数需要生成 DNS 事务 ID。
    *   为了生成事务 ID，会调用 `__res_randomid()` 函数。

**Frida hook 示例调试步骤:**

假设你想观察 `__res_randomid` 的返回值：

```python
import frida
import sys

package_name = "你的应用包名"  # 将此处替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__res_randomid"), {
    onEnter: function(args) {
        console.log("[*] Calling __res_randomid");
    },
    onLeave: function(retval) {
        console.log("[*] __res_randomid returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida-tools。
2. **找到目标应用的包名:**  在 Android 设备上找到你要调试的应用的包名。
3. **运行 Frida 脚本:**  将上面的 Python 代码保存为一个文件（例如 `hook_res_randomid.py`），并将 `package_name` 替换为你应用的包名。然后在终端中运行 `python hook_res_randomid.py`。
4. **操作目标应用:**  在 Android 设备上操作你的应用，使其发起网络请求，从而触发 DNS 查询。
5. **查看 Frida 输出:**  Frida 会拦截对 `__res_randomid` 函数的调用，并在终端中打印出调用信息和返回值。

**更进一步的 Hook 示例 (查看内部状态):**

如果你想查看 `__res_randomid` 内部的一些变量，可以修改 Frida 脚本：

```python
import frida
import sys

package_name = "你的应用包名"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__res_randomid"), {
    onEnter: function(args) {
        console.log("[*] Calling __res_randomid");
    },
    onLeave: function(retval) {
        console.log("[*] __res_randomid returned: " + retval);
        // 读取内部变量的值
        var ru_x_ptr = Module.findExportByName("libc.so", "ru_x");
        var ru_x = ptr(ru_x_ptr).readU16();
        console.log("[*] ru_x: " + ru_x);

        var ru_seed_ptr = Module.findExportByName("libc.so", "ru_seed");
        var ru_seed = ptr(ru_seed_ptr).readU16();
        console.log("[*] ru_seed: " + ru_seed);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**注意:** 直接访问全局变量可能会受到 ASLR (地址空间布局随机化) 的影响。在更复杂的场景中，你可能需要找到基地址并计算偏移量。另外，符号的导出情况可能因 Android 版本和编译选项而异。

总而言之，`res_random.c` 文件在 Android 的 DNS 解析过程中扮演着重要的角色，它负责生成看似随机且不易重复的事务 ID，确保 DNS 查询的正确性和安全性。开发者通常不需要直接操作这个文件中的函数，而是通过上层 API 间接使用其功能。使用 Frida 可以帮助我们深入了解其内部运作机制。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/net/res_random.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* $OpenBSD: res_random.c,v 1.23 2015/10/05 02:57:16 guenther Exp $ */

/*
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * Copyright 2008 Damien Miller <djm@openbsd.org>
 * All rights reserved.
 *
 * Theo de Raadt <deraadt@openbsd.org> came up with the idea of using
 * such a mathematical system to generate more random (yet non-repeating)
 * ids to solve the resolver/named problem.  But Niels designed the
 * actual system based on the constraints.
 *
 * Later modified by Damien Miller to wrap the LCG output in a 15-bit
 * permutation generator based on a Luby-Rackoff block cipher. This
 * ensures the output is non-repeating and preserves the MSB twiddle
 * trick, but makes it more resistant to LCG prediction.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * seed = random 15bit
 * n = prime, g0 = generator to n,
 * j = random so that gcd(j,n-1) == 1
 * g = g0^j mod n will be a generator again.
 *
 * X[0] = random seed.
 * X[n] = a*X[n-1]+b mod m is a Linear Congruential Generator
 * with a = 7^(even random) mod m, 
 *      b = random with gcd(b,m) == 1
 *      m = 31104 and a maximal period of m-1.
 *
 * The transaction id is determined by:
 * id[n] = seed xor (g^X[n] mod n)
 *
 * Effectivly the id is restricted to the lower 15 bits, thus
 * yielding two different cycles by toggling the msb on and off.
 * This avoids reuse issues caused by reseeding.
 *
 * The output of this generator is then randomly permuted though a
 * custom 15 bit Luby-Rackoff block cipher.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <resolv.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "thread_private.h"

#define RU_OUT  	180	/* Time after wich will be reseeded */
#define RU_MAX		30000	/* Uniq cycle, avoid blackjack prediction */
#define RU_GEN		2	/* Starting generator */
#define RU_N		32749	/* RU_N-1 = 2*2*3*2729 */
#define RU_AGEN		7	/* determine ru_a as RU_AGEN^(2*rand) */
#define RU_M		31104	/* RU_M = 2^7*3^5 - don't change */
#define RU_ROUNDS	11	/* Number of rounds for permute (odd) */

struct prf_ctx {
	/* PRF lookup table for odd rounds (7 bits input to 8 bits output) */
	u_char prf7[(RU_ROUNDS / 2) * (1 << 7)];

	/* PRF lookup table for even rounds (8 bits input to 7 bits output) */
	u_char prf8[((RU_ROUNDS + 1) / 2) * (1 << 8)];
};

#define PFAC_N 3
static const u_int16_t pfacts[PFAC_N] = {
	2, 
	3,
	2729
};

static u_int16_t ru_x;
static u_int16_t ru_seed, ru_seed2;
static u_int16_t ru_a, ru_b;
static u_int16_t ru_g;
static u_int16_t ru_counter = 0;
static u_int16_t ru_msb = 0;
static struct prf_ctx *ru_prf = NULL;
static time_t ru_reseed;
static pid_t ru_pid;

static u_int16_t pmod(u_int16_t, u_int16_t, u_int16_t);
static void res_initid(void);

/*
 * Do a fast modular exponation, returned value will be in the range
 * of 0 - (mod-1)
 */
static u_int16_t
pmod(u_int16_t gen, u_int16_t exp, u_int16_t mod)
{
	u_int16_t s, t, u;

	s = 1;
	t = gen;
	u = exp;

	while (u) {
		if (u & 1)
			s = (s * t) % mod;
		u >>= 1;
		t = (t * t) % mod;
	}
	return (s);
}

/*
 * 15-bit permutation based on Luby-Rackoff block cipher
 */
static u_int
permute15(u_int in)
{
	int i;
	u_int left, right, tmp;

	if (ru_prf == NULL)
		return in;

	left = (in >> 8) & 0x7f;
	right = in & 0xff;

	/*
	 * Each round swaps the width of left and right. Even rounds have
	 * a 7-bit left, odd rounds have an 8-bit left.	Since this uses an
	 * odd number of rounds, left is always 8 bits wide at the end.
	 */
	for (i = 0; i < RU_ROUNDS; i++) {
		if ((i & 1) == 0)
			tmp = ru_prf->prf8[(i << (8 - 1)) | right] & 0x7f;
		else
			tmp = ru_prf->prf7[((i - 1) << (7 - 1)) | right];
		tmp ^= left;
		left = right;
		right = tmp;
	}

	return (right << 8) | left;
}

/* 
 * Initializes the seed and chooses a suitable generator. Also toggles 
 * the msb flag. The msb flag is used to generate two distinct
 * cycles of random numbers and thus avoiding reuse of ids.
 *
 * This function is called from res_randomid() when needed, an 
 * application does not have to worry about it.
 */
static void 
res_initid(void)
{
	u_int16_t j, i;
	u_int32_t tmp;
	int noprime = 1;
	struct timespec ts;

	ru_x = arc4random_uniform(RU_M);

	/* 15 bits of random seed */
	tmp = arc4random();
	ru_seed = (tmp >> 16) & 0x7FFF;
	ru_seed2 = tmp & 0x7FFF;

	/* Determine the LCG we use */
	tmp = arc4random();
	ru_b = (tmp & 0xfffe) | 1;
	ru_a = pmod(RU_AGEN, (tmp >> 16) & 0xfffe, RU_M);
	while (ru_b % 3 == 0)
		ru_b += 2;
	
	j = arc4random_uniform(RU_N);

	/* 
	 * Do a fast gcd(j,RU_N-1), so we can find a j with
	 * gcd(j, RU_N-1) == 1, giving a new generator for
	 * RU_GEN^j mod RU_N
	 */

	while (noprime) {
		for (i = 0; i < PFAC_N; i++)
			if (j % pfacts[i] == 0)
				break;

		if (i >= PFAC_N)
			noprime = 0;
		else 
			j = (j + 1) % RU_N;
	}

	ru_g = pmod(RU_GEN, j, RU_N);
	ru_counter = 0;

	/* Initialise PRF for Luby-Rackoff permutation */
	if (ru_prf == NULL)
		ru_prf = malloc(sizeof(*ru_prf));
	if (ru_prf != NULL)
		arc4random_buf(ru_prf, sizeof(*ru_prf));

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ru_reseed = ts.tv_sec + RU_OUT;
	ru_msb = ru_msb == 0x8000 ? 0 : 0x8000; 
}

u_int
__res_randomid(void)
{
	struct timespec ts;
	pid_t pid;
	u_int r;
	_THREAD_PRIVATE_MUTEX(random);

	clock_gettime(CLOCK_MONOTONIC, &ts);
	pid = getpid();

	_THREAD_PRIVATE_MUTEX_LOCK(random);

	if (ru_counter >= RU_MAX || ts.tv_sec > ru_reseed || pid != ru_pid) {
		res_initid();
		ru_pid = pid;
	}

	/* Linear Congruential Generator */
	ru_x = (ru_a * ru_x + ru_b) % RU_M;
	ru_counter++;

	r = permute15(ru_seed ^ pmod(ru_g, ru_seed2 + ru_x, RU_N)) | ru_msb;

	_THREAD_PRIVATE_MUTEX_UNLOCK(random);

	return (r);
}
DEF_STRONG(__res_randomid);

#if 0
int
main(int argc, char **argv)
{
	int i, n;
	u_int16_t wert;

	res_initid();

	printf("Generator: %u\n", ru_g);
	printf("Seed: %u\n", ru_seed);
	printf("Reseed at %ld\n", ru_reseed);
	printf("Ru_X: %u\n", ru_x);
	printf("Ru_A: %u\n", ru_a);
	printf("Ru_B: %u\n", ru_b);

	n = argc > 1 ? atoi(argv[1]) : 60001;
	for (i=0;i<n;i++) {
		wert = res_randomid();
		printf("%u\n", wert);
	}
	return 0;
}
#endif
```