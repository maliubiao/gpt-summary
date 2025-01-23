Response:
Let's break down the thought process for analyzing this ChaCha code snippet and generating the comprehensive response.

**1. Understanding the Request:**

The request is to analyze a C source file (`chacha_private.h` and implicitly `chacha-merged.c`), specifically focusing on its functionality, relation to Android, libc functions, dynamic linking (if applicable), potential errors, and how Android utilizes it. The output needs to be in Chinese. The request also asks for examples, explanations, and even Frida hook examples.

**2. Initial Code Examination and Identification:**

The first step is to skim the code to understand its general structure and purpose. Key observations include:

* **Headers and Typedefs:**  `typedef unsigned char u8;`, `typedef unsigned int u32;`, and the `chacha_ctx` struct clearly point towards a cryptographic algorithm dealing with byte and integer data.
* **Macros:** Macros like `U8C`, `U32C`, `ROTL32`, `U8TO32_LITTLE`, `U32TO8_LITTLE`, `ROTATE`, `XOR`, `PLUS`, `PLUSONE`, and `QUARTERROUND` strongly suggest a block cipher or stream cipher implementation. The names themselves give hints about their operations (rotate, XOR, addition).
* **Constants:** `sigma` and `tau` look like initialization constants.
* **Functions:** `chacha_keysetup`, `chacha_ivsetup`, and `chacha_encrypt_bytes` are the core functions, suggesting key/IV setup and the encryption/decryption process. The function name `chacha_encrypt_bytes` suggests it can operate on a byte stream. The `KEYSTREAM_ONLY` preprocessor directive hints at potential different modes of operation.

**3. Connecting to Cryptography Concepts:**

Based on the observed elements, the code clearly implements the ChaCha stream cipher. Key terms like "key," "IV," "rounds," "quarter round" are all indicative of this. Knowing this helps guide the analysis.

**4. Deconstructing Functionality:**

Now, let's examine each function in detail:

* **`chacha_ctx`:** This is the context structure that holds the internal state of the ChaCha algorithm. The `input` array stores the initial key, IV, and counter values.
* **Macros:**  Each macro's purpose needs to be understood:
    * `U8TO32_LITTLE` and `U32TO8_LITTLE`:  Handle byte order conversion (little-endian). This is crucial for cross-platform compatibility.
    * `ROTL32`: Performs a left rotation, a standard operation in many cryptographic algorithms.
    * `XOR`, `PLUS`: Basic bitwise and arithmetic operations used in the core transformation.
    * `QUARTERROUND`:  The fundamental building block of the ChaCha round function. Understanding its steps is essential. This involves substitutions and permutations of the state.
* **`chacha_keysetup`:** This function initializes the `chacha_ctx` with the provided key. It handles both 128-bit and 256-bit keys, using the `tau` and `sigma` constants accordingly. This confirms the algorithm supports different key sizes.
* **`chacha_ivsetup`:**  Initializes the Initialization Vector (IV) and sets the initial counter values within the `chacha_ctx`. The counter is important for generating different keystreams from the same key and IV.
* **`chacha_encrypt_bytes`:** This is the core encryption/decryption function (since it's a stream cipher, encryption and decryption are the same operation). It:
    * Creates a working copy of the internal state (`j0` to `j15`).
    * Performs 20 rounds of the ChaCha core transformation (10 double rounds, each consisting of 4 `QUARTERROUND` calls on columns and then diagonals).
    * Adds the initial state to the transformed state.
    * XORs the resulting keystream with the input message (`m`) to produce the ciphertext (`c`). The `#ifndef KEYSTREAM_ONLY` block controls whether this XOR operation is performed, allowing for pure keystream generation.
    * Increments the counter (`j12` and `j13`).
    * Handles cases where the input byte count is less than 64.

**5. Relating to Android:**

The crucial point is the file path: `bionic/libc/upstream-openbsd/lib/libc/crypt/`. This immediately tells us:

* **Part of `libc`:** This is a fundamental part of Android's C library.
* **From OpenBSD:**  Android often incorporates security-related code from OpenBSD due to its strong security focus and auditing.
* **`crypt` directory:**  Clearly related to cryptographic functionality.

Therefore, ChaCha is likely used within Android for various encryption/decryption tasks. Examples include network security (TLS/SSL), file encryption, and potentially within VPN or other security-sensitive components.

**6. Dynamic Linking (and why it's less relevant here):**

This particular code snippet is a header file and a C source file. It defines functions that are *compiled into* `libc.so`. It doesn't represent a separate shared library that would be dynamically linked. The dynamic linker is involved when an application uses functions from `libc.so`, but this code itself doesn't demonstrate dynamic linking. Therefore, while understanding dynamic linking is important for Android development, it's not a central focus for *this specific file*. A mental note is made of this.

**7. Potential Errors and Usage:**

Consider common mistakes when using cryptographic libraries:

* **Incorrect key or IV:**  Leading to decryption failures.
* **Reusing IVs with the same key:**  A major security vulnerability in stream ciphers.
* **Not handling the full output buffer:** Potential buffer overflows if the output buffer is too small.
* **Misunderstanding the counter:** Incorrect counter management can lead to keystream reuse.

**8. Android Framework/NDK Usage:**

Think about how Android applications would access this. The NDK allows developers to use C/C++ code. They would typically use higher-level cryptographic APIs provided by the Android framework (e.g., `javax.crypto` in Java or the `android_crypto_*` APIs in native code). These higher-level APIs would, in turn, likely call down into the `libc` implementation of ChaCha (or other ciphers). The framework provides abstractions to make cryptography easier and safer to use.

**9. Frida Hooking:**

Consider which functions would be interesting to hook for analysis:

* `chacha_keysetup`: To inspect the key being used.
* `chacha_ivsetup`: To see the IV.
* `chacha_encrypt_bytes`: To examine the plaintext and ciphertext.

Frida provides the mechanisms to intercept these function calls, inspect arguments, and modify behavior.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use clear and concise language. Provide code examples and diagrams where helpful (though the provided example didn't lend itself well to complex diagrams). Address each part of the original request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this directly used by apps via dynamic linking?"  **Correction:**  Realized it's part of `libc`, so the linking is implicit when apps use `libc` functions. The focus should be on *how* `libc` functions are implemented and how apps *indirectly* use this code.
* **Considering the level of detail:**  Decided to explain the core ChaCha algorithm concepts (rounds, quarter rounds) without going into extreme mathematical detail, focusing on the practical aspects and how the code implements them.
* **Frida example specifics:** Initially thought of a more complex hooking scenario, but simplified it to focus on the key functions and basic logging for clarity.

By following these steps, systematically analyzing the code, and connecting it to the broader Android context, a comprehensive and accurate answer can be generated. The focus was on understanding the *what*, *why*, and *how* of this specific code within the Android ecosystem.
## 对 bionic/libc/upstream-openbsd/lib/libc/crypt/chacha_private.handroid 的源代码文件分析

这个文件 `chacha_private.handroid` (以及隐含的 `chacha-merged.c`) 是 Android Bionic libc 库中实现了 ChaCha 流密码算法的源代码。它来源于 OpenBSD 的 libc 库，体现了 Android 在安全和密码学方面对成熟开源项目的借鉴。

**功能列举:**

这个文件的核心功能是提供了 ChaCha 流密码算法的实现，具体包括：

1. **`chacha_ctx` 结构体定义:** 定义了 ChaCha 算法的上下文信息，包括内部状态 `input` 数组。
2. **常量定义:** 定义了字节和整数类型的宏，以及用于密钥设置的常量字符串 `sigma` 和 `tau`。
3. **基本操作宏:** 定义了诸如字节/整数转换（大小端序）、循环左移、异或、加法等基本操作的宏，这些是 ChaCha 算法的基础。
4. **`QUARTERROUND` 宏:**  定义了 ChaCha 算法中的四分之一轮操作，是核心的计算单元。
5. **`chacha_keysetup` 函数:**  用于初始化 ChaCha 上下文，根据提供的密钥 (k) 和密钥长度 (kbits) 设置内部状态。支持 128 位和 256 位密钥。
6. **`chacha_ivsetup` 函数:** 用于初始化 ChaCha 上下文的初始向量 (IV)，并初始化内部状态中的计数器部分。
7. **`chacha_encrypt_bytes` 函数:**  用于加密或解密指定长度的字节流。由于 ChaCha 是流密码，加密和解密操作相同，都是与生成的密钥流进行异或。

**与 Android 功能的关系及举例说明:**

ChaCha 作为一个高效且安全的流密码算法，在 Android 系统中有着广泛的应用，主要在需要加密或认证的场景。

* **TLS/SSL 加密:** Android 系统网络通信中广泛使用的 TLS/SSL 协议，其加密套件中可能包含 ChaCha20 算法。例如，在 HTTPS 连接中，如果客户端和服务器协商使用了基于 ChaCha20 的加密套件，那么底层就会调用到这里的 ChaCha 实现进行数据加密。
* **VPN 连接:** VPN 应用为了保护用户数据传输的安全，也会使用加密算法，ChaCha20 由于其高性能，常被用于移动设备上的 VPN 连接。
* **文件加密:**  Android 系统或应用可能使用 ChaCha20 对敏感文件进行加密存储。
* **Android Keystore 系统:** Android Keystore 系统用于安全地存储加密密钥。虽然 Keystore 本身不直接使用 ChaCha 进行密钥加密，但基于 Keystore 保护的密钥可能会被用于初始化 ChaCha 算法，从而加密其他数据。

**libc 函数的功能实现详解:**

* **`chacha_keysetup(chacha_ctx *x, const u8 *k, u32 kbits)`:**
    * **功能:**  根据给定的密钥 `k` 和密钥长度 `kbits` 初始化 `chacha_ctx` 结构体 `x`。
    * **实现:**
        1. 将密钥 `k` 的前 16 字节（或全部，取决于密钥长度）以小端序转换为 32 位整数，并存储到 `x->input` 数组的特定位置 (索引 4-7)。
        2. 根据 `kbits` 的值（128 或 256），选择对应的常量字符串 `sigma` 或 `tau`。
        3. 如果密钥长度为 256 位，则将 `k` 指针偏移 16 字节，取剩余 16 字节。
        4. 将选定的常量字符串（`sigma` 或 `tau`）的前 16 字节以小端序转换为 32 位整数，并存储到 `x->input` 数组的起始位置 (索引 0-3)。
        5. 如果密钥长度为 128 位，则将密钥 `k` 的内容再次以小端序转换为 32 位整数，并存储到 `x->input` 数组的后续位置 (索引 8-11)。

* **`chacha_ivsetup(chacha_ctx *x, const u8 *iv)`:**
    * **功能:** 根据给定的初始向量 `iv` 初始化 `chacha_ctx` 结构体 `x`。
    * **实现:**
        1. 将 `x->input` 数组的索引 12 和 13 的值设置为 0。这两个位置通常用于存储块计数器的低位和高位，初始时设置为 0。
        2. 将初始向量 `iv` 的前 8 字节以小端序转换为两个 32 位整数，并存储到 `x->input` 数组的索引 14 和 15 的位置。

* **`chacha_encrypt_bytes(chacha_ctx *x, const u8 *m, u8 *c, u32 bytes)`:**
    * **功能:** 使用 ChaCha 算法加密或解密长度为 `bytes` 的字节流 `m`，结果存储到 `c` 中。
    * **实现:**
        1. **检查字节数:** 如果 `bytes` 为 0，则直接返回。
        2. **保存初始状态:** 将 `x->input` 数组的内容复制到局部变量 `j0` 到 `j15`，作为 ChaCha 轮函数的初始状态。
        3. **处理小块数据:** 如果待处理的字节数 `bytes` 小于 64 字节，则将 `m` 的内容复制到临时缓冲区 `tmp`，并将 `m` 和 `c` 指针指向 `tmp`，以便统一处理逻辑。
        4. **进行多轮计算:** 进入一个循环，每次处理 64 字节的数据（或者剩余的不足 64 字节的数据）。
            * 将当前状态 `j0` 到 `j15` 复制到工作变量 `x0` 到 `x15`。
            * 进行 20 轮的 ChaCha 核心运算。每一轮包含 4 次对列的 `QUARTERROUND` 操作和 4 次对角线的 `QUARTERROUND` 操作。
            * 将经过 20 轮运算后的状态 `x0` 到 `x15` 与初始状态 `j0` 到 `j15` 进行逐元素相加。
            * **加密/解密:**  如果 `KEYSTREAM_ONLY` 未定义（通常情况），则将运算后的状态 `x0` 到 `x15` 与输入数据 `m` 的对应 4 字节进行异或，得到加密/解密后的数据。
            * **更新计数器:**  递增计数器 `j12`。如果 `j12` 溢出，则递增 `j13`。
            * **输出结果:** 将运算后的状态 `x0` 到 `x15` 以小端序转换回 8 字节，并存储到输出缓冲区 `c` 中。
        5. **处理剩余数据:** 如果处理的字节数小于 64，则将临时缓冲区 `c` 的内容复制回目标缓冲区 `ctarget`。
        6. **更新上下文:** 将更新后的计数器值 `j12` 和 `j13` 写回 `x->input` 数组。
        7. **循环处理:** 如果还有剩余的字节需要处理，则更新 `m` 和 `c` 指针，并继续循环。

**涉及 dynamic linker 的功能:**

这个源代码文件本身并没有直接涉及 dynamic linker 的功能。它是 `libc.so` 的一部分，当应用程序调用 `libc` 提供的与加密相关的函数时，dynamic linker 负责加载 `libc.so` 共享库，并将应用程序的函数调用链接到 `libc.so` 中对应的 ChaCha 实现。

**so 布局样本:**

```
libc.so
├── ...
├── __libc_init  // libc 初始化函数
├── malloc       // 内存分配函数
├── free         // 内存释放函数
├── printf       // 格式化输出函数
├── ...
└── crypt        // 加密相关函数
    ├── chacha_keysetup
    ├── chacha_ivsetup
    └── chacha_encrypt_bytes
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序的代码中调用了需要 ChaCha 功能的函数时（例如，通过 OpenSSL 或其他加密库间接调用），编译器会生成对 `libc.so` 中相关函数的未定义引用。
2. **加载时链接:**  当 Android 系统加载应用程序时，dynamic linker (如 `linker64` 或 `linker`) 会解析应用程序的可执行文件，并识别出对共享库 `libc.so` 的依赖。
3. **查找共享库:** dynamic linker 会在预定义的路径中查找 `libc.so` 文件。
4. **加载共享库:** 找到 `libc.so` 后，dynamic linker 会将其加载到内存中。
5. **符号解析:** dynamic linker 会解析 `libc.so` 的符号表，找到应用程序中未定义引用对应的符号（例如 `chacha_encrypt_bytes`）在 `libc.so` 中的地址。
6. **重定位:** dynamic linker 会修改应用程序代码中的未定义引用，将其指向 `libc.so` 中对应函数的实际内存地址。
7. **调用:** 当应用程序执行到调用 ChaCha 相关函数的代码时，程序会跳转到 `libc.so` 中 `chacha_encrypt_bytes` 函数的地址执行。

**逻辑推理的假设输入与输出:**

假设我们有以下输入：

* **密钥 (k):**  一个 32 字节的字符串 "This is a 32-byte secret key for ChaCha."
* **初始向量 (iv):** 一个 8 字节的字符串 "my_nonce"
* **明文 (m):** 一个 64 字节的字符串 "This is a 64-byte message to be encrypted using ChaCha algorithm."

**步骤:**

1. **`chacha_keysetup(ctx, k, 256)`:**  使用密钥 `k` 初始化 ChaCha 上下文 `ctx`。`sigma` 常量会被使用。
2. **`chacha_ivsetup(ctx, iv)`:** 使用初始向量 `iv` 初始化 ChaCha 上下文 `ctx` 的计数器部分。
3. **`chacha_encrypt_bytes(ctx, m, c, 64)`:**  使用初始化后的上下文 `ctx` 加密明文 `m`，结果存储到密文 `c` 中。

**输出 (密文 c):** 由于 ChaCha 是流密码，其输出取决于密钥、初始向量和明文。这里无法精确给出密文的十六进制表示，但可以肯定的是 `c` 将是一个长度为 64 字节的随机字节序列，与明文 `m` 不同。使用相同的密钥和初始向量再次加密相同的明文将产生相同的密文。

**用户或编程常见的使用错误:**

1. **密钥和 IV 的错误使用:**
    * **密钥长度错误:**  `chacha_keysetup` 期望的密钥长度是 128 位或 256 位。使用错误的密钥长度会导致初始化失败或产生不可预测的结果。
    * **重复使用相同的密钥和 IV:** 对于流密码，使用相同的密钥和 IV 加密不同的消息会暴露出消息之间的信息，这是一个严重的安全漏洞。
    * **IV 的保密性:** 虽然 IV 不需要像密钥那样保密，但其随机性和唯一性至关重要。

   **示例:**

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include "chacha_private.h" // 假设头文件存在

   int main() {
       chacha_ctx ctx;
       unsigned char key[16] = "insecure_key_123"; // 128-bit key
       unsigned char iv[8] = "same_iv";
       unsigned char plaintext[64] = "This is message 1";
       unsigned char ciphertext[64];

       chacha_keysetup(&ctx, key, 128);
       chacha_ivsetup(&ctx, iv);
       chacha_encrypt_bytes(&ctx, plaintext, ciphertext, sizeof(plaintext));

       printf("Ciphertext 1: ");
       for (int i = 0; i < sizeof(ciphertext); i++) {
           printf("%02x", ciphertext[i]);
       }
       printf("\n");

       unsigned char plaintext2[64] = "This is message 2";
       unsigned char ciphertext2[64];

       // 错误：没有重新初始化 IV
       chacha_encrypt_bytes(&ctx, plaintext2, ciphertext2, sizeof(plaintext2));

       printf("Ciphertext 2: ");
       for (int i = 0; i < sizeof(ciphertext2); i++) {
           printf("%02x", ciphertext2[i]);
       }
       printf("\n");

       return 0;
   }
   ```

   在这个例子中，对于第二条消息，没有重新初始化 IV，这违反了流密码的安全使用原则。

2. **缓冲区溢出:**  如果输出缓冲区 `c` 的大小小于要加密/解密的字节数 `bytes`，会导致缓冲区溢出。

   **示例:**

   ```c
   chacha_ctx ctx;
   unsigned char key[32] = {/* ... */};
   unsigned char iv[8] = {/* ... */};
   unsigned char plaintext[100] = {/* ... */};
   unsigned char ciphertext[50]; // 输出缓冲区太小

   chacha_keysetup(&ctx, key, 256);
   chacha_ivsetup(&ctx, iv);
   chacha_encrypt_bytes(&ctx, plaintext, ciphertext, sizeof(plaintext)); // 可能导致溢出
   ```

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例:**

Android Framework 或 NDK 通常不会直接调用 `chacha_private.h` 中定义的函数。而是通过更高层次的加密 API 来间接使用。例如：

1. **Java Framework (javax.crypto):**  开发者在 Java 代码中使用 `javax.crypto` 包提供的 `Cipher` 类进行加密操作时，底层实现可能会调用到 Bionic libc 中的 ChaCha 实现。例如，使用 "ChaCha20" 算法名称创建 `Cipher` 对象。
2. **NDK (Android Crypto APIs):**  Native 代码可以使用 Android 提供的 NDK Crypto API，这些 API 最终也会调用到 Bionic libc 的加密实现。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `chacha_encrypt_bytes` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const chacha_encrypt_bytes_ptr = Module.findExportByName("libc.so", "chacha_encrypt_bytes");

  if (chacha_encrypt_bytes_ptr) {
    Interceptor.attach(chacha_encrypt_bytes_ptr, {
      onEnter: function (args) {
        console.log("[+] chacha_encrypt_bytes called");
        const ctx = args[0];
        const m = args[1];
        const c = args[2];
        const bytes = args[3].toInt();

        console.log("    Context:", ctx);
        console.log("    Plaintext:", hexdump(m, { length: Math.min(bytes, 64) }));
        console.log("    Bytes:", bytes);
      },
      onLeave: function (retval) {
        console.log("    Return value:", retval);
        // 这里可以检查加密后的密文
      }
    });
  } else {
    console.log("[-] chacha_encrypt_bytes not found in libc.so");
  }
} else {
  console.log("[-] Frida hook example is for ARM/ARM64 architectures.");
}

```

**解释:**

1. **检查架构:**  Hook 代码通常需要考虑不同的 CPU 架构。
2. **查找函数地址:** `Module.findExportByName("libc.so", "chacha_encrypt_bytes")` 尝试在 `libc.so` 中查找 `chacha_encrypt_bytes` 函数的地址。
3. **附加拦截器:** `Interceptor.attach()` 用于在函数调用时插入自定义的代码。
4. **`onEnter`:**  在目标函数执行前调用。`args` 数组包含了函数的参数。
    * `args[0]`: `chacha_ctx *x` 指针。
    * `args[1]`: `const u8 *m` 指针 (明文)。
    * `args[2]`: `u8 *c` 指针 (密文缓冲区)。
    * `args[3]`: `u32 bytes` (加密/解密的字节数)。
    * 代码打印了函数被调用的信息、上下文指针、部分明文内容和字节数。
5. **`onLeave`:** 在目标函数执行后调用。`retval` 包含了函数的返回值。
6. **错误处理:** 检查是否成功找到目标函数。

通过这个 Frida Hook 示例，你可以在 Android 设备上运行包含 ChaCha 加密的应用程序，并观察 `chacha_encrypt_bytes` 函数的调用，查看传递给它的参数，从而理解 Android 系统如何一步步地使用底层的 ChaCha 实现。

总而言之，`chacha_private.handroid` 是 Android 系统中实现 ChaCha 流密码算法的关键源代码，它为 Android 的各种加密功能提供了基础。理解其功能和使用方式对于分析 Android 安全机制至关重要。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/crypt/chacha_private.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

/* $OpenBSD: chacha_private.h,v 1.3 2022/02/28 21:56:29 dtucker Exp $ */

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct
{
  u32 input[16]; /* could be compressed */
} chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

static void
chacha_keysetup(chacha_ctx *x,const u8 *k,u32 kbits)
{
  const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

static void
chacha_ivsetup(chacha_ctx *x,const u8 *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

static void
chacha_encrypt_bytes(chacha_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = NULL;
  u8 tmp[64];
  u_int i;

  if (!bytes) return;

  j0 = x->input[0];
  j1 = x->input[1];
  j2 = x->input[2];
  j3 = x->input[3];
  j4 = x->input[4];
  j5 = x->input[5];
  j6 = x->input[6];
  j7 = x->input[7];
  j8 = x->input[8];
  j9 = x->input[9];
  j10 = x->input[10];
  j11 = x->input[11];
  j12 = x->input[12];
  j13 = x->input[13];
  j14 = x->input[14];
  j15 = x->input[15];

  for (;;) {
    if (bytes < 64) {
      for (i = 0;i < bytes;++i) tmp[i] = m[i];
      m = tmp;
      ctarget = c;
      c = tmp;
    }
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (i = 20;i > 0;i -= 2) {
      QUARTERROUND( x0, x4, x8,x12)
      QUARTERROUND( x1, x5, x9,x13)
      QUARTERROUND( x2, x6,x10,x14)
      QUARTERROUND( x3, x7,x11,x15)
      QUARTERROUND( x0, x5,x10,x15)
      QUARTERROUND( x1, x6,x11,x12)
      QUARTERROUND( x2, x7, x8,x13)
      QUARTERROUND( x3, x4, x9,x14)
    }
    x0 = PLUS(x0,j0);
    x1 = PLUS(x1,j1);
    x2 = PLUS(x2,j2);
    x3 = PLUS(x3,j3);
    x4 = PLUS(x4,j4);
    x5 = PLUS(x5,j5);
    x6 = PLUS(x6,j6);
    x7 = PLUS(x7,j7);
    x8 = PLUS(x8,j8);
    x9 = PLUS(x9,j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

#ifndef KEYSTREAM_ONLY
    x0 = XOR(x0,U8TO32_LITTLE(m + 0));
    x1 = XOR(x1,U8TO32_LITTLE(m + 4));
    x2 = XOR(x2,U8TO32_LITTLE(m + 8));
    x3 = XOR(x3,U8TO32_LITTLE(m + 12));
    x4 = XOR(x4,U8TO32_LITTLE(m + 16));
    x5 = XOR(x5,U8TO32_LITTLE(m + 20));
    x6 = XOR(x6,U8TO32_LITTLE(m + 24));
    x7 = XOR(x7,U8TO32_LITTLE(m + 28));
    x8 = XOR(x8,U8TO32_LITTLE(m + 32));
    x9 = XOR(x9,U8TO32_LITTLE(m + 36));
    x10 = XOR(x10,U8TO32_LITTLE(m + 40));
    x11 = XOR(x11,U8TO32_LITTLE(m + 44));
    x12 = XOR(x12,U8TO32_LITTLE(m + 48));
    x13 = XOR(x13,U8TO32_LITTLE(m + 52));
    x14 = XOR(x14,U8TO32_LITTLE(m + 56));
    x15 = XOR(x15,U8TO32_LITTLE(m + 60));
#endif

    j12 = PLUSONE(j12);
    if (!j12) {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);
    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    if (bytes <= 64) {
      if (bytes < 64) {
        for (i = 0;i < bytes;++i) ctarget[i] = c[i];
      }
      x->input[12] = j12;
      x->input[13] = j13;
      return;
    }
    bytes -= 64;
    c += 64;
#ifndef KEYSTREAM_ONLY
    m += 64;
#endif
  }
}
```