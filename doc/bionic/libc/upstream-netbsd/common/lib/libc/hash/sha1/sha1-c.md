Response:
Let's break down the thought process to generate the detailed explanation of the `sha1.c` file.

1. **Understand the Core Request:** The primary goal is to analyze the provided `sha1.c` source code from Android Bionic and explain its functionality, its relation to Android, and provide insights into its implementation, including dynamic linking, usage errors, and how Android frameworks utilize it.

2. **Identify the Primary Function:** The code clearly implements the SHA-1 hashing algorithm. This is the central theme around which all explanations will revolve.

3. **Break Down Functionality:**  Start by listing the major functions present in the code:
    * `SHA1Transform`: The core hashing function for a single block.
    * `SHA1Init`: Initializes the SHA-1 context.
    * `SHA1Update`: Processes input data in chunks.
    * `SHA1Final`: Completes the hashing process and produces the digest.

4. **Explain Each Function in Detail:** For each function, consider the following aspects:
    * **Purpose:** What does the function do?
    * **Mechanism:** How does it achieve its purpose (step-by-step within the code)? This involves explaining the bitwise operations, the round functions, and the data flow.
    * **Parameters:** What are the inputs and their types?
    * **Return Value/Output:** What does the function produce?

5. **Connect to Android:** Think about how SHA-1 is used in Android. Common use cases include:
    * **File Integrity:** Verifying downloaded files or system components.
    * **Git:**  Android's source code management uses Git, which relies heavily on SHA-1 for object identification and integrity.
    * **Cryptographic Primitives:** Although SHA-1 is considered cryptographically broken for many security-sensitive applications, it might still be used in less critical areas or for legacy compatibility.
    * **Package Management (Historically):** While newer Android versions use stronger hashes, older versions or parts of the system might still use SHA-1 for APK verification.

6. **Address Dynamic Linking (though limited in this specific file):**  The code itself doesn't directly *perform* dynamic linking. However, it *is* part of `libc`, which is a shared library. Therefore, the explanation should cover:
    * **How `libc.so` is structured:** Basic layout of code, data, and symbol tables.
    * **The linking process:** Briefly explain how the dynamic linker resolves symbols when an application uses SHA-1. A simple example using `dlsym` or direct function calls can illustrate this.

7. **Consider Logical Reasoning and Input/Output:**  Choose a simple example (like the "abc" test vector) and manually walk through the initial steps conceptually. Mention the input, the transformations, and the expected output. Due to the complexity of SHA-1, a complete manual calculation isn't feasible, but demonstrating the initial process is valuable.

8. **Identify Common Usage Errors:** Think about mistakes developers might make when using SHA-1:
    * **Incorrect Initialization:** Forgetting to call `SHA1Init`.
    * **Partial Updates:**  Not calling `SHA1Final` to complete the process.
    * **Buffer Overflows:** Although less likely with the provided API, always a concern with C and memory manipulation.
    * **Misinterpreting the Digest:** Not understanding the format or endianness of the output.

9. **Trace the Android Framework/NDK Usage:** This requires thinking about the layers of Android:
    * **NDK:** How can a native C/C++ application use SHA-1? Through the standard `<openssl/sha.h>` or the Bionic provided `<sys/sha1.h>`. Provide a simple NDK example.
    * **Android Framework (Java):** How does the Java layer access this functionality?  Through Java's `MessageDigest` class, which internally calls native code. Explain the JNI bridge.
    * **Hooking with Frida:** Show how to use Frida to intercept calls to the SHA-1 functions, demonstrating how to observe parameters and results.

10. **Structure and Language:** Organize the information logically using clear headings and bullet points. Use precise and understandable Chinese. Explain technical terms where necessary. Use code blocks for examples.

11. **Refine and Review:**  Read through the entire explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have forgotten to explicitly mention the endianness considerations in the `blk0` macro. Reviewing the code helps catch such details. Also, ensure the Frida example is practical and easy to understand.

**Self-Correction/Refinement Example during the process:**

* **Initial Thought:**  Focus heavily on the bitwise operations in `SHA1Transform`.
* **Correction:** While important, explain the *purpose* of each stage (message padding, initialization, processing blocks) before diving too deep into the bit manipulations. The higher-level flow is crucial for understanding. Also, recognize that a complete manual walkthrough of the rounds is impractical for a general explanation. Focus on the *structure* of the rounds instead.
* **Initial Thought:**  Assume everyone understands dynamic linking.
* **Correction:**  Provide a concise explanation of what dynamic linking is and how `libc.so` fits into it, even if this specific file doesn't *perform* the linking itself. The context is important.
* **Initial Thought:**  Just list the Frida code.
* **Correction:** Explain *what* the Frida code is doing – intercepting function calls, logging parameters and results. This makes the example more instructive.

By following this structured thought process, breaking down the problem into smaller parts, and refining the explanation along the way, a comprehensive and informative answer can be generated.
好的，让我们详细分析一下 `bionic/libc/upstream-netbsd/common/lib/libc/hash/sha1/sha1.c` 这个文件。

**文件功能概述**

这个 `sha1.c` 文件实现了 SHA-1（Secure Hash Algorithm 1）散列算法。SHA-1 是一种密码学哈希函数，它接收任意长度的输入（也称为“消息”），并产生一个 160 位（20 字节）的固定大小的哈希值，通常以 40 个十六进制数字表示。

**主要功能:**

1. **计算消息的 SHA-1 摘要 (Digest):**  这是 SHA-1 的核心功能。给定一段数据，该文件中的代码能够计算出其唯一的 SHA-1 哈希值。即使输入数据发生微小的变化，产生的哈希值也会有很大不同。

2. **初始化 SHA-1 上下文 (`SHA1Init`):**  在使用 SHA-1 进行哈希计算之前，需要初始化一个上下文结构 `SHA1_CTX`。这个结构体保存了中间状态，以便可以逐步处理输入数据。

3. **更新 SHA-1 上下文 (`SHA1Update`):**  可以分块地向 SHA-1 上下文提供输入数据。`SHA1Update` 函数会将这些数据融入到当前的哈希计算中。这对于处理大型文件或流式数据非常有用。

4. **完成 SHA-1 计算并生成摘要 (`SHA1Final`):**  在所有数据都通过 `SHA1Update` 处理之后，调用 `SHA1Final` 函数来完成计算。这个函数会进行必要的填充操作，并生成最终的 20 字节 SHA-1 摘要。

**与 Android 功能的关系及举例**

SHA-1 在 Android 中有多种用途，尽管由于安全原因，它在新系统中已逐渐被更安全的哈希算法（如 SHA-256）取代。以下是一些例子：

1. **文件完整性校验:**
   - **例子:**  在 Android 系统启动时，或者在安装应用程序时，系统可能会使用 SHA-1 来校验关键系统文件或 APK 文件的完整性。如果文件的 SHA-1 摘要与预期值不符，则表明文件可能已损坏或被篡改。
   - **说明:** Android Framework 可以读取文件的内容，然后调用 `SHA1Init`、多次 `SHA1Update`（分块读取文件内容），最后调用 `SHA1Final` 来计算文件的 SHA-1 摘要，并与预期的摘要进行比较。

2. **Git 版本控制:**
   - **例子:** Android 的源代码使用 Git 进行管理。Git 内部大量使用 SHA-1 来标识和校验版本库中的对象（commits, trees, blobs）。
   - **说明:** 当你使用 `git clone` 下载 Android 源代码时，Git 会使用 SHA-1 来验证下载的数据是否完整且未被修改。底层的 Git 工具很可能会调用 libc 提供的 SHA-1 实现。

3. **唯一标识符生成 (不推荐用于安全敏感场景):**
   - **例子:**  在某些情况下，可能会使用 SHA-1 来生成基于某些数据（例如设备 ID 的组合）的唯一标识符。但是，由于 SHA-1 的碰撞脆弱性，这不应该用于安全敏感的场景。
   - **说明:**  开发者可能会组合一些设备的唯一信息，然后使用 `SHA1Init`, `SHA1Update`, `SHA1Final` 计算出一个 SHA-1 摘要作为标识符。

4. **历史遗留的加密功能:**
   - **例子:** 在较老的 Android 版本或某些库中，SHA-1 可能被用作某些加密协议的一部分。
   - **说明:** 相关的加密模块会调用 libc 提供的 SHA-1 函数来实现特定的加密逻辑。

**libc 函数的实现细节**

下面详细解释 `sha1.c` 中关键 libc 函数的实现：

1. **`SHA1Init(SHA1_CTX *context)`:**
   - **功能:** 初始化 SHA-1 上下文结构体 `context`。
   - **实现:**
     - 将 `context->state` 数组的前五个元素设置为 SHA-1 算法规定的初始哈希值（常量）：`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`, `0xC3D2E1F0`。
     - 将 `context->count[0]` 和 `context->count[1]` 设置为 0。这两个变量用于记录已处理的输入数据的总比特数。

2. **`SHA1Update(SHA1_CTX *context, const uint8_t *data, unsigned int len)`:**
   - **功能:** 更新 SHA-1 上下文，处理 `len` 字节的输入数据 `data`。
   - **实现:**
     - 首先，获取当前上下文中已缓存但未处理的数据长度 `j`。
     - 更新已处理数据的总比特数 `context->count`。
     - 如果当前缓存的数据加上新输入的数据超过 64 字节（SHA-1 的处理块大小），则将缓存填满，并调用 `SHA1Transform` 处理这 64 字节的数据块。
     - 循环处理输入数据，每次处理 64 字节的块，直到剩余数据不足 64 字节。
     - 将剩余的输入数据复制到 `context->buffer` 中缓存起来，等待下一次 `SHA1Update` 或 `SHA1Final` 调用。

3. **`SHA1Final(uint8_t digest[20], SHA1_CTX *context)`:**
   - **功能:** 完成 SHA-1 计算，将最终的 20 字节摘要写入 `digest` 数组。
   - **实现:**
     - **填充 (Padding):**  在输入数据的末尾添加填充比特，使得总长度模 512 位等于 448 位。填充由一个比特 "1" 后面跟着零个或多个比特 "0" 组成。
     - **追加长度:** 将原始输入数据的长度（以比特为单位）追加到填充后的数据末尾，长度占用 64 位。
     - **最后一次转换:** 使用填充后的数据块（可能需要多次 `SHA1Update` 来填充）调用 `SHA1Transform`。
     - **输出摘要:** 将 `context->state` 数组中的五个 32 位整数连接起来，按照大端字节序排列，形成最终的 20 字节 SHA-1 摘要，并复制到 `digest` 数组中。

4. **`SHA1Transform(uint32_t state[5], const uint8_t buffer[64])`:**
   - **功能:** 处理一个 512 位的消息块，更新 SHA-1 的内部状态。
   - **实现:** 这是 SHA-1 算法的核心。
     - 将输入的 64 字节数据块 `buffer` 转换为 16 个 32 位字。字节序可能需要调整（通过 `blk0` 宏）。
     - 使用消息扩展函数（`blk` 宏）将这 16 个字扩展为 80 个字。
     - 使用四个不同的循环（通常称为轮），每个循环包含 20 个操作。每个循环使用不同的非线性函数 (R0, R1, R2, R3, R4) 和不同的加法常数。
     - 在每个操作中，对五个工作变量 `a`, `b`, `c`, `d`, `e` 进行一系列的位运算（循环移位、与、或、异或等），并将扩展后的消息字和轮常数加入其中。
     - 将计算后的工作变量的值加回到 `state` 数组中，更新内部状态。

**动态链接功能**

`sha1.c` 文件本身并不直接涉及动态链接的实现。它是 `libc.so` 的一部分，而 `libc.so` 是一个共享库，通过动态链接器加载到进程的地址空间。

**`libc.so` 布局样本:**

```
libc.so:
    .text         # 包含 SHA1Init, SHA1Update, SHA1Final, SHA1Transform 等函数的代码
    .rodata       # 包含只读数据，例如 SHA-1 的初始常量
    .data         # 包含全局变量（如果有）
    .bss          # 包含未初始化的全局变量
    .dynsym       # 动态符号表，列出可被其他共享库引用的符号（例如 SHA1Init）
    .dynstr       # 动态字符串表，存储符号名称
    .plt          # 程序链接表，用于延迟绑定
    .got.plt      # 全局偏移表，存储外部符号的地址
```

**链接的处理过程:**

1. **编译时:** 当应用程序或另一个共享库需要使用 SHA-1 功能时，编译器会生成对 `SHA1Init`、`SHA1Update`、`SHA1Final` 等符号的未解析引用。链接器会将这些引用记录在生成的可执行文件或共享库的动态链接信息中。

2. **加载时:** 当 Android 系统加载包含这些未解析引用的应用程序或共享库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会介入。

3. **查找共享库:** 动态链接器会根据预定义的搜索路径（例如 `/system/lib64`, `/vendor/lib64` 等）查找所需的共享库 `libc.so`。

4. **符号解析:** 动态链接器会遍历 `libc.so` 的 `.dynsym` 和 `.dynstr` 表，查找与未解析引用匹配的符号。例如，它会找到 `SHA1Init`、`SHA1Update` 等符号的地址。

5. **重定位:** 动态链接器会将找到的符号地址写入到调用模块的 `.got.plt` 表中。当程序首次调用 `SHA1Init` 时，会通过 `.plt` 跳转到 `.got.plt` 中存储的地址，从而执行 `libc.so` 中的 `SHA1Init` 函数。后续调用可以直接通过 `.got.plt` 获取函数地址，提高效率（延迟绑定）。

**假设输入与输出 (逻辑推理)**

假设我们有输入字符串 "abc"。

1. **初始化:** 调用 `SHA1Init` 初始化 `SHA1_CTX`。
   - `context->state` 被设置为初始常量。
   - `context->count` 被设置为 0。

2. **更新:** 调用 `SHA1Update(context, "abc", 3)`。
   - "abc" 被复制到 `context->buffer`。
   - `context->count` 更新为 24 (3 字节 * 8 位/字节)。

3. **完成:** 调用 `SHA1Final(digest, context)`。
   - **填充:** 添加填充比特 "1" 和 "0"，直到数据长度为 448 位。
   - **追加长度:** 追加原始长度 24 (以比特表示)。
   - **转换:**  `SHA1Transform` 会被调用来处理包含 "abc"、填充和长度的块。
   - **输出:** `digest` 数组将包含 SHA-1 摘要：`A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D` (十六进制)。

**用户或编程常见的使用错误**

1. **未初始化上下文:** 在调用 `SHA1Update` 或 `SHA1Final` 之前忘记调用 `SHA1Init`。这会导致使用未初始化的内存，产生不可预测的结果。
   ```c
   SHA1_CTX context;
   // 忘记调用 SHA1Init(&context);
   SHA1Update(&context, "data", 4); // 错误的使用
   ```

2. **多次调用 `SHA1Final`:**  `SHA1Final` 会完成计算并重置上下文。多次调用 `SHA1Final` 在同一个上下文中会导致错误的结果。
   ```c
   SHA1_CTX context;
   uint8_t digest[20];
   SHA1Init(&context);
   SHA1Update(&context, "data", 4);
   SHA1Final(digest, &context);
   SHA1Final(digest, &context); // 错误：上下文已重置
   ```

3. **摘要缓冲区过小:** 传递给 `SHA1Final` 的 `digest` 缓冲区小于 20 字节。这会导致缓冲区溢出。
   ```c
   SHA1_CTX context;
   uint8_t digest[10]; // 缓冲区过小
   SHA1Init(&context);
   SHA1Update(&context, "data", 4);
   SHA1Final(digest, &context); // 潜在的缓冲区溢出
   ```

4. **错误处理分块数据:** 在处理分块数据时，没有正确维护上下文状态，或者在 `SHA1Final` 之前就过早地认为哈希计算完成。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 使用:**
   - C/C++ 代码可以通过 NDK 调用 libc 提供的 SHA-1 函数。
   - NDK 中通常会包含 `<openssl/sha.h>` 或 `<sys/sha1.h>` 头文件，定义了 `SHA1_CTX` 结构体和相关的函数原型。
   - 开发者可以直接调用 `SHA1Init`, `SHA1Update`, `SHA1Final`。

   ```c++
   #include <sys/sha1.h>
   #include <stdio.h>
   #include <string.h>

   void calculate_sha1(const char *data) {
       SHA1_CTX context;
       unsigned char digest[20];

       SHA1Init(&context);
       SHA1Update(&context, (const unsigned char*)data, strlen(data));
       SHA1Final(digest, &context);

       printf("SHA-1 digest of '%s': ", data);
       for (int i = 0; i < 20; i++) {
           printf("%02x", digest[i]);
       }
       printf("\n");
   }

   int main() {
       calculate_sha1("hello");
       return 0;
   }
   ```

2. **Android Framework 使用 (Java 层):**
   - Android Framework 的 Java 层通常通过 `java.security.MessageDigest` 类来使用哈希算法。
   - 当你调用 `MessageDigest.getInstance("SHA-1")` 时，Java 安全框架会查找相应的提供者 (Provider)。
   - 在 Android 中，Bouncy Castle 或 Conscrypt 等安全提供者会注册支持 SHA-1 算法。
   - 这些提供者的实现最终会通过 JNI (Java Native Interface) 调用到 native 代码，即 `bionic/libc` 中的 SHA-1 实现。

   ```java
   import java.security.MessageDigest;
   import java.security.NoSuchAlgorithmException;

   public class SHA1Example {
       public static void main(String[] args) {
           try {
               MessageDigest md = MessageDigest.getInstance("SHA-1");
               String input = "hello";
               byte[] inputBytes = input.getBytes();
               byte[] digestBytes = md.digest(inputBytes);

               StringBuilder hexString = new StringBuilder();
               for (byte b : digestBytes) {
                   hexString.append(String.format("%02x", b));
               }
               System.out.println("SHA-1 digest of '" + input + "': " + hexString.toString());
           } catch (NoSuchAlgorithmException e) {
               e.printStackTrace();
           }
       }
   }
   ```

**Frida Hook 示例**

你可以使用 Frida 来 hook `SHA1Update` 函数，观察其输入参数和行为。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(['com.example.myapp']) # 替换为你的应用包名
session = device.attach(pid)
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "SHA1Update"), {
    onEnter: function(args) {
        console.log("[*] SHA1Update called!");
        var ctx = ptr(args[0]);
        var data = ptr(args[1]);
        var len = args[2].toInt();
        console.log("    Context: " + ctx);
        console.log("    Data Pointer: " + data);
        console.log("    Length: " + len);
        if (len > 0) {
            console.log("    Data: " + hexdump(data.readByteArray(len), { ansi: true }));
        }
    },
    onLeave: function(retval) {
        console.log("[*] SHA1Update returned: " + retval);
    }
});
""")
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **`Interceptor.attach`:**  使用 Frida 的 `Interceptor` API 拦截 `libc.so` 中的 `SHA1Update` 函数。
2. **`onEnter`:** 在 `SHA1Update` 函数被调用之前执行。
   - 打印 "SHA1Update called!"。
   - 获取函数参数：`context` 指针、`data` 指针和 `len`。
   - 打印参数的值。
   - 如果 `len` 大于 0，则读取 `data` 指向的内存区域，并使用 `hexdump` 打印数据的十六进制表示。
3. **`onLeave`:** 在 `SHA1Update` 函数执行完毕后执行，打印返回值。

通过运行这个 Frida 脚本，当目标应用调用 `SHA1Update` 时，你可以在 Frida 控制台中看到调用的上下文、传入的数据指针、数据长度以及实际的数据内容。这可以帮助你调试和理解 Android Framework 或 NDK 如何使用 libc 的 SHA-1 实现。

希望这个详细的解释能够帮助你理解 `bionic/libc/upstream-netbsd/common/lib/libc/hash/sha1/sha1.c` 文件的功能和在 Android 中的应用。

Prompt: 
```
这是目录为bionic/libc/upstream-netbsd/common/lib/libc/hash/sha1/sha1.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: sha1.c,v 1.6 2009/11/06 20:31:18 joerg Exp $	*/
/*	$OpenBSD: sha1.c,v 1.9 1997/07/23 21:12:32 kstailey Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 *
 * Test Vectors (from FIPS PUB 180-1)
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
 */

#define SHA1HANDSOFF		/* Copies data before messing with it. */

#include <sys/cdefs.h>

#if defined(_KERNEL) || defined(_STANDALONE)
__KERNEL_RCSID(0, "$NetBSD: sha1.c,v 1.6 2009/11/06 20:31:18 joerg Exp $");

#include <lib/libkern/libkern.h>

#else

#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: sha1.c,v 1.6 2009/11/06 20:31:18 joerg Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <assert.h>
#include <string.h>

#endif

#include <sys/types.h>
#include <sys/sha1.h>


#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
#endif

#if !HAVE_SHA1_H

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/*
 * blk0() and blk() perform the initial expand.
 * I got the idea of expanding during the round function from SSLeay
 */
#if BYTE_ORDER == LITTLE_ENDIAN
# define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
# define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/*
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


#if !defined(_KERNEL) && !defined(_STANDALONE)
#if defined(__weak_alias)
__weak_alias(SHA1Transform,_SHA1Transform)
__weak_alias(SHA1Init,_SHA1Init)
__weak_alias(SHA1Update,_SHA1Update)
__weak_alias(SHA1Final,_SHA1Final)
#endif
#endif

typedef union {
    uint8_t c[64];
    uint32_t l[16];
} CHAR64LONG16;

/* old sparc64 gcc could not compile this */
#undef SPARC64_GCC_WORKAROUND
#if defined(__sparc64__) && defined(__GNUC__) && __GNUC__ < 3
#define SPARC64_GCC_WORKAROUND
#endif

#ifdef SPARC64_GCC_WORKAROUND
void do_R01(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *);
void do_R2(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *);
void do_R3(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *);
void do_R4(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *);

#define nR0(v,w,x,y,z,i) R0(*v,*w,*x,*y,*z,i)
#define nR1(v,w,x,y,z,i) R1(*v,*w,*x,*y,*z,i)
#define nR2(v,w,x,y,z,i) R2(*v,*w,*x,*y,*z,i)
#define nR3(v,w,x,y,z,i) R3(*v,*w,*x,*y,*z,i)
#define nR4(v,w,x,y,z,i) R4(*v,*w,*x,*y,*z,i)

void
do_R01(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *block)
{
    nR0(a,b,c,d,e, 0); nR0(e,a,b,c,d, 1); nR0(d,e,a,b,c, 2); nR0(c,d,e,a,b, 3);
    nR0(b,c,d,e,a, 4); nR0(a,b,c,d,e, 5); nR0(e,a,b,c,d, 6); nR0(d,e,a,b,c, 7);
    nR0(c,d,e,a,b, 8); nR0(b,c,d,e,a, 9); nR0(a,b,c,d,e,10); nR0(e,a,b,c,d,11);
    nR0(d,e,a,b,c,12); nR0(c,d,e,a,b,13); nR0(b,c,d,e,a,14); nR0(a,b,c,d,e,15);
    nR1(e,a,b,c,d,16); nR1(d,e,a,b,c,17); nR1(c,d,e,a,b,18); nR1(b,c,d,e,a,19);
}

void
do_R2(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *block)
{
    nR2(a,b,c,d,e,20); nR2(e,a,b,c,d,21); nR2(d,e,a,b,c,22); nR2(c,d,e,a,b,23);
    nR2(b,c,d,e,a,24); nR2(a,b,c,d,e,25); nR2(e,a,b,c,d,26); nR2(d,e,a,b,c,27);
    nR2(c,d,e,a,b,28); nR2(b,c,d,e,a,29); nR2(a,b,c,d,e,30); nR2(e,a,b,c,d,31);
    nR2(d,e,a,b,c,32); nR2(c,d,e,a,b,33); nR2(b,c,d,e,a,34); nR2(a,b,c,d,e,35);
    nR2(e,a,b,c,d,36); nR2(d,e,a,b,c,37); nR2(c,d,e,a,b,38); nR2(b,c,d,e,a,39);
}

void
do_R3(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *block)
{
    nR3(a,b,c,d,e,40); nR3(e,a,b,c,d,41); nR3(d,e,a,b,c,42); nR3(c,d,e,a,b,43);
    nR3(b,c,d,e,a,44); nR3(a,b,c,d,e,45); nR3(e,a,b,c,d,46); nR3(d,e,a,b,c,47);
    nR3(c,d,e,a,b,48); nR3(b,c,d,e,a,49); nR3(a,b,c,d,e,50); nR3(e,a,b,c,d,51);
    nR3(d,e,a,b,c,52); nR3(c,d,e,a,b,53); nR3(b,c,d,e,a,54); nR3(a,b,c,d,e,55);
    nR3(e,a,b,c,d,56); nR3(d,e,a,b,c,57); nR3(c,d,e,a,b,58); nR3(b,c,d,e,a,59);
}

void
do_R4(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *e, CHAR64LONG16 *block)
{
    nR4(a,b,c,d,e,60); nR4(e,a,b,c,d,61); nR4(d,e,a,b,c,62); nR4(c,d,e,a,b,63);
    nR4(b,c,d,e,a,64); nR4(a,b,c,d,e,65); nR4(e,a,b,c,d,66); nR4(d,e,a,b,c,67);
    nR4(c,d,e,a,b,68); nR4(b,c,d,e,a,69); nR4(a,b,c,d,e,70); nR4(e,a,b,c,d,71);
    nR4(d,e,a,b,c,72); nR4(c,d,e,a,b,73); nR4(b,c,d,e,a,74); nR4(a,b,c,d,e,75);
    nR4(e,a,b,c,d,76); nR4(d,e,a,b,c,77); nR4(c,d,e,a,b,78); nR4(b,c,d,e,a,79);
}
#endif

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
void SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a, b, c, d, e;
    CHAR64LONG16 *block;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 workspace;
#endif

    _DIAGASSERT(buffer != 0);
    _DIAGASSERT(state != 0);

#ifdef SHA1HANDSOFF
    block = &workspace;
    (void)memcpy(block, buffer, 64);
#else
    block = (CHAR64LONG16 *)(void *)buffer;
#endif

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

#ifdef SPARC64_GCC_WORKAROUND
    do_R01(&a, &b, &c, &d, &e, block);
    do_R2(&a, &b, &c, &d, &e, block);
    do_R3(&a, &b, &c, &d, &e, block);
    do_R4(&a, &b, &c, &d, &e, block);
#else
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
#endif

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}


/*
 * SHA1Init - Initialize new context
 */
void SHA1Init(SHA1_CTX *context)
{

    _DIAGASSERT(context != 0);

    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/*
 * Run your data through this.
 */
void SHA1Update(SHA1_CTX *context, const uint8_t *data, unsigned int len)
{
    unsigned int i, j;

    _DIAGASSERT(context != 0);
    _DIAGASSERT(data != 0);

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
	context->count[1] += (len>>29)+1;
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
	(void)memcpy(&context->buffer[j], data, (i = 64-j));
	SHA1Transform(context->state, context->buffer);
	for ( ; i + 63 < len; i += 64)
	    SHA1Transform(context->state, &data[i]);
	j = 0;
    } else {
	i = 0;
    }
    (void)memcpy(&context->buffer[j], &data[i], len - i);
}


/*
 * Add padding and return the message digest.
 */
void SHA1Final(uint8_t digest[20], SHA1_CTX *context)
{
    unsigned int i;
    uint8_t finalcount[8];

    _DIAGASSERT(digest != 0);
    _DIAGASSERT(context != 0);

    for (i = 0; i < 8; i++) {
	finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
	 >> ((3-(i & 3)) * 8) ) & 255);	 /* Endian independent */
    }
    SHA1Update(context, (const uint8_t *)"\200", 1);
    while ((context->count[0] & 504) != 448)
	SHA1Update(context, (const uint8_t *)"\0", 1);
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */

    if (digest) {
	for (i = 0; i < 20; i++)
	    digest[i] = (uint8_t)
		((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
}

#endif /* HAVE_SHA1_H */

"""

```