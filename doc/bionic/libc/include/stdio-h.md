Response:
Let's break down the thought process for answering the request about `bionic/libc/include/stdio.h`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided `stdio.h` header file from Android's Bionic library and explain its functionality, its connection to Android, the implementation details of its functions, its interaction with the dynamic linker, potential user errors, and how it's accessed from the Android framework and NDK. The answer needs to be in Chinese.

**2. Initial Assessment of the Header File:**

* **It's a standard C library header:** The filename `stdio.h` immediately suggests it deals with standard input/output operations. Keywords like `FILE`, `printf`, `scanf`, `fopen`, `fclose` confirm this.
* **Copyright and Origins:** The header includes copyright information from the University of California and mentions OpenBSD and NetBSD, indicating it's derived from a BSD-like implementation. This is important context for understanding the historical development and design choices.
* **Android-Specific Macros:**  The presence of `#if __ANDROID_API__ < 24` and `__INTRODUCED_IN(version)` macros signals Android-specific modifications and versioning. This will be crucial for explaining Android integration.
* **Function Declarations:** The bulk of the file consists of function declarations, along with some type definitions (`typedef`) and macro definitions (`#define`).
* **Conditional Compilation:**  `#if defined(__USE_GNU)` and `#if defined(__USE_BSD)` suggest that the header adapts to different system configurations.
* **Fortification:** The inclusion of `<bits/fortify/stdio.h>` indicates security-related features.

**3. Structuring the Answer:**

To address all aspects of the request comprehensively and clearly, a structured approach is necessary. I decided on the following sections:

* **文件功能概述 (Overview of File Functionality):** Start with a high-level summary of what `stdio.h` does.
* **与 Android 功能的关系 (Relationship with Android Functionality):**  Focus on how this fundamental C library component is essential for the Android operating system.
* **Libc 函数功能详解 (Detailed Explanation of Libc Function Functionality):**  Explain the purpose of the most important functions. *Initially, I considered explaining every function, but realized it would be too verbose and less helpful. Focusing on common and illustrative functions is better.*  I selected `printf`, `scanf`, `fopen`, `fclose`, `fread`, `fwrite`, `fgets`, `fputs`, and `rename` as good examples covering various I/O operations.
* **动态链接器相关功能 (Dynamic Linker Related Functionality):** Address the dynamic linking aspect. This involves explaining how `stdio` functions are part of `libc.so` and how the linker resolves these symbols.
* **常见用户或编程错误 (Common User or Programming Errors):**  Highlight typical mistakes developers make when using `stdio` functions.
* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):** Explain the path from Android application code to the `stdio.h` functions within Bionic.
* **Frida Hook 示例 (Frida Hook Example):** Provide practical examples of using Frida to intercept `stdio` function calls for debugging.

**4. Populating Each Section:**

* **功能概述:**  Emphasize that `stdio.h` provides standard C input/output functions.
* **Android 关系:**  Explain that it's a core part of Bionic and used extensively by the Android system and apps. Provide examples like logging and file access.
* **Libc 函数详解:**  For each selected function, provide:
    * **功能描述 (Function Description):** A concise explanation of its purpose.
    * **实现方式 (Implementation):**  A simplified overview of how the function works internally. *I focused on the general logic rather than delving into low-level kernel interactions for brevity.*
    * **Android 关联 (Android Relevance):**  Specific examples of how the function is used in Android.
    * **示例 (Example):**  Simple code snippets demonstrating basic usage.
    * **常见错误 (Common Errors):** Typical mistakes developers make.
* **动态链接器:**
    * **SO 布局 (SO Layout):** Describe the structure of `libc.so` and where `stdio` functions reside.
    * **链接过程 (Linking Process):** Explain symbol resolution during application loading. Mention PLT/GOT.
* **常见错误:** Include errors like buffer overflows with `gets`, incorrect format specifiers, and forgetting to close files.
* **Framework/NDK 到达:** Explain the hierarchy: Java code uses Android SDK, NDK provides C/C++ access, which links against Bionic. Give examples of NDK usage.
* **Frida Hook:**  Provide concrete JavaScript code to hook `printf` and demonstrate logging arguments.

**5. Addressing Specific Constraints and Details:**

* **Function Implementation Details:**  While the request asked for detailed implementation explanations, for a header file, the "implementation" is in the corresponding `.c` files (like `stdio.c`). Therefore, my explanation focused on the general logic and interaction with the operating system. For example, `printf`'s implementation involves parsing the format string and calling lower-level functions to write to the output stream.
* **Dynamic Linker Details:** I explained the basic concepts of shared libraries and symbol resolution. Providing an exact `so` layout is impractical without analyzing the compiled `libc.so`. Instead, I described the conceptual structure.
* **Logic Inference/Assumptions:**  For the examples, I made standard assumptions about file paths, input data, and program behavior. These are illustrative.
* **Error Handling:** I included common errors associated with `stdio` functions.
* **Android Framework/NDK Path:**  I outlined the typical development flow in Android.
* **Frida Hook:** I provided a practical and easy-to-understand example.

**6. Language and Tone:**

The response is written in simplified Chinese, using clear and concise language. Technical terms are used appropriately. The tone is informative and helpful.

**7. Review and Refinement:**

After drafting the initial response, I reread the request and my answer to ensure all points were addressed adequately and accurately. I checked for clarity, completeness, and any potential misunderstandings. For instance, I made sure to distinguish between the header file and the actual implementation of the functions. I also reviewed the Frida example for correctness.

This iterative process of understanding the request, structuring the answer, populating sections with details, and reviewing for accuracy led to the final comprehensive response.
这个 `bionic/libc/include/stdio.handroid` 文件是 Android Bionic C 库中的 `stdio.h` 头文件。它定义了标准 C 语言输入/输出库的接口。这意味着它声明了各种用于处理输入和输出的函数、宏和类型。

**它的功能：**

1. **基本输入/输出操作:** 定义了用于执行基本输入/输出操作的函数，例如从文件读取数据、向文件写入数据、格式化输入/输出等。
2. **文件操作:**  声明了用于打开、关闭、读取、写入和定位文件的函数。
3. **格式化输入/输出:** 提供了 `printf` 和 `scanf` 系列函数，用于执行格式化的输入和输出操作。
4. **内存流操作:** 定义了操作内存缓冲区的函数，例如 `sprintf` 和 `sscanf`，以及 `fmemopen` 和 `open_memstream`。
5. **错误处理:** 提供了用于检查和清除文件错误状态的函数，例如 `ferror` 和 `clearerr`。
6. **标准流:** 定义了标准输入、标准输出和标准错误流 (`stdin`, `stdout`, `stderr`)。
7. **缓冲控制:** 提供了控制文件缓冲行为的函数，例如 `setbuf` 和 `setvbuf`。
8. **临时文件操作:** 提供了创建和管理临时文件的函数，例如 `tmpfile` 和 `tmpnam`。
9. **文件定位:** 提供了用于在文件中移动读写位置的函数，例如 `fseek` 和 `ftell`。
10. **其他实用函数:**  包含了一些其他有用的函数，例如 `rename`（重命名文件）、`remove`（删除文件）、`perror`（打印错误消息）等。

**与 Android 功能的关系及举例说明：**

`stdio.h` 中定义的函数是 Android 系统及其应用程序的基础构建块。几乎所有的 Android 应用和服务都会直接或间接地使用这些函数进行输入输出操作。

* **日志记录:** Android 系统和应用广泛使用 `printf` 和相关函数将日志信息输出到标准输出或通过重定向输出到日志文件。例如，在 Java 代码中使用 `Log.d()` 或在 Native 代码中使用 `__android_log_print()`，最终会调用到 Bionic 的 `stdio` 函数。
* **文件访问:**  Android 应用需要读写文件，例如读取配置文件、保存用户数据等。`fopen`、`fclose`、`fread`、`fwrite` 等函数是实现这些操作的关键。例如，一个应用可能使用 `fopen` 打开一个保存用户设置的文件，使用 `fread` 读取设置，并在修改后使用 `fwrite` 保存。
* **进程间通信 (IPC):** 虽然不是 `stdio` 的直接功能，但管道 (pipe) 等 IPC 机制会使用文件描述符，而 `stdio` 函数如 `fdopen` 可以将文件描述符转换为 `FILE` 指针，方便进行缓冲 I/O 操作。
* **网络编程:**  虽然 `stdio` 主要处理本地文件，但在某些情况下，网络编程可能会使用 `stdio` 提供的缓冲功能，例如通过 `fdopen` 将 socket 文件描述符转换为 `FILE` 指针。
* **NDK 开发:** 使用 Android NDK 开发原生 C/C++ 代码时，开发者会直接使用 `stdio.h` 中声明的函数进行输入输出操作。例如，一个游戏引擎可能使用 `fopen` 加载资源文件，使用 `printf` 打印调试信息。

**详细解释每一个 libc 函数的功能是如何实现的：**

由于 `stdio.h` 是一个头文件，它只包含函数声明和宏定义，并没有包含具体的函数实现。这些函数的实现代码位于 Bionic 库的 `libc.so` 中。

以下是一些常用函数的简要实现原理（更底层的实现会涉及到系统调用）：

* **`printf(const char *format, ...)`:**
    * **功能:**  将格式化的数据输出到标准输出。
    * **实现:**  解析 `format` 字符串中的格式说明符 (`%d`, `%s`, `%f` 等)，从可变参数列表中获取对应的值，并将它们格式化成字符串，然后调用底层的 `write` 系统调用将字符串写入到与标准输出关联的文件描述符 (通常是 1)。
* **`scanf(const char *format, ...)`:**
    * **功能:**  从标准输入读取格式化的数据。
    * **实现:**  解析 `format` 字符串中的格式说明符，从标准输入读取数据，并将读取到的数据按照格式说明符的指示转换为相应的数据类型，然后存储到提供的变量地址中。底层会调用 `read` 系统调用从与标准输入关联的文件描述符 (通常是 0) 读取数据。
* **`fopen(const char *pathname, const char *mode)`:**
    * **功能:**  打开一个文件。
    * **实现:**  调用底层的 `open` 系统调用，根据 `mode` 参数（例如 "r", "w", "a"）指定打开文件的权限和方式。如果打开成功，会在内存中分配一个 `FILE` 结构体，用于维护文件的相关信息（如文件描述符、缓冲区等），并将文件描述符存储在该结构体中，最后返回指向该结构体的指针。
* **`fclose(FILE *stream)`:**
    * **功能:**  关闭一个打开的文件。
    * **实现:**  首先刷新与该文件流关联的缓冲区，将缓冲区中的数据写入文件（如果文件是以写入模式打开的）。然后调用底层的 `close` 系统调用关闭文件描述符。最后，释放之前为 `FILE` 结构体分配的内存。
* **`fread(void *ptr, size_t size, size_t nmemb, FILE *stream)`:**
    * **功能:**  从文件中读取指定数量的数据块。
    * **实现:**  检查文件流的缓冲区，如果缓冲区中有足够的数据，则直接从缓冲区读取。否则，调用底层的 `read` 系统调用从文件描述符读取数据到缓冲区，然后再从缓冲区复制数据到 `ptr` 指向的内存。
* **`fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)`:**
    * **功能:**  向文件中写入指定数量的数据块。
    * **实现:**  检查文件流的缓冲区，如果缓冲区有足够的空间，则将数据复制到缓冲区。否则，先将缓冲区中的内容写入文件（调用底层的 `write` 系统调用），然后再将新的数据复制到缓冲区。当调用 `fflush` 或 `fclose` 时，缓冲区中的数据会被最终写入文件。
* **`fgets(char *str, int num, FILE *stream)`:**
    * **功能:**  从文件中读取一行字符串。
    * **实现:**  从文件流的缓冲区中读取字符，直到遇到换行符 (`\n`)、文件结束符 (EOF) 或读取了 `num - 1` 个字符为止。将读取到的字符存储到 `str` 指向的缓冲区，并在末尾添加空字符 (`\0`)。如果缓冲区中没有数据，则调用底层的 `read` 系统调用。
* **`fputs(const char *str, FILE *stream)`:**
    * **功能:**  向文件中写入一个字符串。
    * **实现:**  将 `str` 指向的字符串复制到文件流的缓冲区中。如果缓冲区已满，则调用底层的 `write` 系统调用将缓冲区内容写入文件。
* **`rename(const char *oldpath, const char *newpath)`:**
    * **功能:**  重命名一个文件或目录。
    * **实现:**  调用底层的 `rename` 系统调用，该系统调用会修改文件系统的元数据，将 `oldpath` 指定的文件或目录重命名为 `newpath`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`stdio.h` 中声明的函数的实现代码位于 `libc.so` 这个共享库中。

**`libc.so` 布局样本（简化）：**

```
libc.so:
    .text:  <-- 包含可执行代码的段
        printf:   <printf 函数的代码>
        scanf:    <scanf 函数的代码>
        fopen:    <fopen 函数的代码>
        ...
    .data:  <-- 包含已初始化的全局变量和静态变量的段
        __sF:     <用于存储标准流 FILE 结构体的数组>
        ...
    .bss:   <-- 包含未初始化的全局变量和静态变量的段
        ...
    .dynsym: <-- 动态符号表，包含导出的符号（函数和变量名）
        printf
        scanf
        fopen
        ...
    .dynstr: <-- 动态字符串表，包含符号表中字符串的名字
        "printf"
        "scanf"
        "fopen"
        ...
    .plt:   <-- 程序链接表，用于延迟绑定动态符号
        printf@plt:
        scanf@plt:
        fopen@plt:
        ...
    .got:   <-- 全局偏移表，用于存储动态符号的运行时地址
        printf@got: 0x0  <-- 初始值为 0，运行时被动态链接器填充
        scanf@got:  0x0
        fopen@got:  0x0
        ...
```

**链接的处理过程：**

1. **编译时链接:** 当编译一个使用 `stdio.h` 中函数的程序时，编译器会生成对这些函数的未解析引用。这些引用会记录在生成的目标文件 ( `.o` 文件) 的符号表中。
2. **动态链接:** 在程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载程序依赖的共享库，例如 `libc.so`。
3. **符号查找:** 动态链接器会检查程序的目标文件中的未解析符号，并尝试在已加载的共享库的动态符号表 (`.dynsym`) 中查找匹配的符号。例如，如果程序调用了 `printf`，链接器会在 `libc.so` 的 `.dynsym` 中查找 `printf`。
4. **重定位:** 一旦找到匹配的符号，动态链接器会将该符号在共享库中的实际地址填充到程序的全局偏移表 (`.got`) 中对应的条目。
5. **延迟绑定 (Lazy Binding):**  通常情况下，为了提高启动速度，动态链接器会使用延迟绑定。这意味着在程序第一次调用一个动态链接的函数时，才会真正进行符号查找和重定位。
    * 当程序第一次调用 `printf` 时，会跳转到程序链接表 (`.plt`) 中 `printf@plt` 的代码。
    * `printf@plt` 中的代码会将控制权交给动态链接器，并告知需要解析 `printf` 符号。
    * 动态链接器执行符号查找和重定位，并将 `printf` 在 `libc.so` 中的实际地址写入 `printf@got` 中。
    * 随后再次调用 `printf` 时，程序会直接跳转到 `printf@got` 中存储的地址，即 `printf` 函数的实际代码，而无需再次经过动态链接器。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们有以下 C 代码片段：

```c
#include <stdio.h>

int main() {
  int age;
  printf("请输入你的年龄：");
  scanf("%d", &age);
  printf("你的年龄是：%d\n", age);
  return 0;
}
```

**假设输入：** `25` (用户在程序运行时输入)

**逻辑推理与输出：**

1. **`printf("请输入你的年龄：");`**:  程序执行到这里，`printf` 函数会被调用，将字符串 "请输入你的年龄：" 输出到标准输出（通常是终端）。
   **输出：** `请输入你的年龄：`

2. **`scanf("%d", &age);`**:  `scanf` 函数被调用，它会尝试从标准输入读取一个整数，并将读取到的值存储到 `age` 变量的内存地址。
   **假设输入：** 用户输入 `25` 并按下回车键。
   `scanf` 成功读取到整数 `25`。

3. **`printf("你的年龄是：%d\n", age);`**:  `printf` 函数被调用，它会格式化字符串 "你的年龄是：%d\n"，将 `age` 变量的值（`25`）替换到 `%d` 的位置。
   **输出：** `你的年龄是：25\n`

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **`scanf` 格式字符串与输入不匹配:**
   ```c
   int num;
   scanf("%d", &num);
   ```
   **错误:** 如果用户输入的是非数字字符，例如 "abc"，`scanf` 将无法正确解析，可能导致 `num` 的值未被初始化或包含垃圾数据。

2. **`printf` 格式字符串与参数类型不匹配:**
   ```c
   int num = 10;
   printf("数字是：%s\n", num); // 应该使用 %d
   ```
   **错误:**  `%s` 用于打印字符串，而 `num` 是一个整数。这会导致未定义的行为，可能打印出乱码或程序崩溃。

3. **缓冲区溢出 (使用 `gets`):**
   ```c
   char buffer[10];
   gets(buffer); // gets 函数不进行边界检查，非常危险
   ```
   **错误:** 如果用户输入的字符串长度超过 `buffer` 的大小，`gets` 会继续写入超出 `buffer` 边界的内存，导致缓冲区溢出，可能覆盖其他数据或代码，引发安全漏洞。**应该使用 `fgets` 代替。**

4. **忘记检查文件操作的返回值:**
   ```c
   FILE *fp = fopen("myfile.txt", "r");
   // 没有检查 fp 是否为 NULL
   char line[100];
   fgets(line, sizeof(line), fp);
   ```
   **错误:** 如果 `fopen` 打开文件失败（例如文件不存在），它会返回 `NULL`。在 `fp` 为 `NULL` 的情况下调用 `fgets` 会导致程序崩溃。应该始终检查文件操作函数的返回值。

5. **忘记关闭文件:**
   ```c
   FILE *fp = fopen("myfile.txt", "w");
   // ... 向文件写入数据 ...
   // 忘记调用 fclose(fp);
   ```
   **错误:**  忘记关闭文件可能导致数据丢失（缓冲区未刷新）或资源泄漏（文件描述符未释放）。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `stdio.h` 的路径：**

1. **Android Framework (Java 代码):**  Android Framework 的 Java 代码通常不直接调用 `stdio.h` 中的函数。
2. **Android Runtime (ART) / Dalvik:**  当 Framework 需要执行 Native 代码时，例如调用 NDK 编译的库，会通过 JNI (Java Native Interface) 进行调用。
3. **NDK 编译的共享库 (.so):**  NDK 开发者可以使用 C/C++ 编写代码，并使用 NDK 工具链将其编译成共享库 (`.so` 文件)。
4. **Bionic (libc.so):** NDK 编译的共享库会链接到 Bionic C 库 (`libc.so`)。当 NDK 代码调用 `stdio.h` 中声明的函数时，最终会调用到 `libc.so` 中对应的实现。

**NDK 到 `stdio.h` 的路径：**

1. **NDK 代码 (C/C++ 代码):** NDK 开发者直接在 C/C++ 代码中包含 `<stdio.h>` 头文件，并调用其中的函数。
2. **编译和链接:** NDK 工具链中的编译器 (clang) 会处理这些调用，并将它们链接到 Bionic C 库 (`libc.so`)。
3. **运行时加载:** 当 Android 应用加载包含这些 NDK 代码的共享库时，动态链接器会加载 `libc.so`，并解析 NDK 代码中对 `stdio` 函数的引用。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `printf` 函数的示例：

```javascript
// attach 到目标进程
function hook_printf() {
    const printfPtr = Module.findExportByName("libc.so", "printf");
    if (printfPtr) {
        Interceptor.attach(printfPtr, {
            onEnter: function (args) {
                const formatString = Memory.readUtf8String(args[0]);
                const formattedArgs = [];
                for (let i = 1; i < args.length; i++) {
                    formattedArgs.push(args[i]);
                }
                console.log(`[printf] Format: ${formatString}, Args: ${formattedArgs}`);
            },
            onLeave: function (retval) {
                // console.log("[printf] Returned:", retval);
            }
        });
        console.log("Hooked printf!");
    } else {
        console.log("Failed to find printf in libc.so");
    }
}

rpc.exports = {
    hook_printf: hook_printf
};
```

**使用步骤：**

1. **保存为 `hook.js` 文件。**
2. **找到目标 Android 进程的 PID。**
3. **使用 Frida 连接到目标进程并执行脚本：**
   ```bash
   frida -U -f <目标应用包名> -l hook.js --no-pause
   # 或者，如果进程已经在运行：
   frida -U <进程名称或 PID> -l hook.js
   ```

**运行结果：**

当目标应用调用 `printf` 函数时，Frida 脚本会拦截该调用，并在控制台上打印 `printf` 函数的格式字符串和参数。

**示例输出：**

```
     ____                          _
    / __/ __ ____ ___ ___  ___  ___(_)
   / /_/ '__/ __ `// _ ` _ \/ _ \/ /
  / __/ / / /_/ // ___/ / //  __/ /
 /_/  /_/  \__,_/ \__/_/ /_/\___/_/
      Runtime Mobile Exploration

[Pixel 5::com.example.myapp]-> Hooked printf!
[printf] Format: 请输入你的年龄：, Args: []
[printf] Format: 你的年龄是：%d
, Args: [25]
```

这个 Frida 示例展示了如何动态地监控和调试 Android 应用中对 `stdio` 函数的调用，这对于理解应用的内部行为和排查问题非常有帮助。你可以修改这个脚本来 Hook 其他 `stdio` 函数，例如 `fopen`、`fclose` 等，以观察应用的文件操作行为。

### 提示词
```
这是目录为bionic/libc/include/stdio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: stdio.h,v 1.35 2006/01/13 18:10:09 miod Exp $	*/
/*	$NetBSD: stdio.h,v 1.18 1996/04/25 18:29:21 jtc Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)stdio.h	5.17 (Berkeley) 6/3/91
 */

#ifndef	_STDIO_H_
#define	_STDIO_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stdarg.h>
#include <stddef.h>

#include <bits/seek_constants.h>

#if __ANDROID_API__ < 24
#include <bits/struct_file.h>
#endif

__BEGIN_DECLS

typedef off_t fpos_t;
typedef off64_t fpos64_t;

struct __sFILE;
typedef struct __sFILE FILE;

#if __ANDROID_API__ >= 23
extern FILE* _Nonnull stdin __INTRODUCED_IN(23);
extern FILE* _Nonnull stdout __INTRODUCED_IN(23);
extern FILE* _Nonnull stderr __INTRODUCED_IN(23);

/* C99 and earlier plus current C++ standards say these must be macros. */
#define stdin stdin
#define stdout stdout
#define stderr stderr
#else
/* Before M the actual symbols for stdin and friends had different names. */
extern FILE __sF[] __REMOVED_IN(23, "Use stdin/stdout/stderr");

#define stdin (&__sF[0])
#define stdout (&__sF[1])
#define stderr (&__sF[2])
#endif

/*
 * The following three definitions are for ANSI C, which took them
 * from System V, which brilliantly took internal interface macros and
 * made them official arguments to setvbuf(), without renaming them.
 * Hence, these ugly _IOxxx names are *supposed* to appear in user code.
 *
 * Although numbered as their counterparts above, the implementation
 * does not rely on this.
 */
#define	_IOFBF	0		/* setvbuf should set fully buffered */
#define	_IOLBF	1		/* setvbuf should set line buffered */
#define	_IONBF	2		/* setvbuf should set unbuffered */

#define	BUFSIZ	1024		/* size of buffer used by setbuf */
#define	EOF	(-1)

/*
 * FOPEN_MAX is a minimum maximum, and is the number of streams that
 * stdio can provide without attempting to allocate further resources
 * (which could fail).  Do not use this for anything.
 */
#define FOPEN_MAX 20
#define FILENAME_MAX 4096

#define L_tmpnam 4096
#define TMP_MAX 308915776

void clearerr(FILE* _Nonnull __fp);
int fclose(FILE* _Nonnull __fp);
__nodiscard int feof(FILE* _Nonnull __fp);
__nodiscard int ferror(FILE* _Nonnull __fp);
int fflush(FILE* _Nullable __fp);
__nodiscard int fgetc(FILE* _Nonnull __fp);
char* _Nullable fgets(char* _Nonnull __buf, int __size, FILE* _Nonnull __fp);
int fprintf(FILE* _Nonnull __fp , const char* _Nonnull __fmt, ...) __printflike(2, 3);
int fputc(int __ch, FILE* _Nonnull __fp);
int fputs(const char* _Nonnull __s, FILE* _Nonnull __fp);
size_t fread(void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp);
int fscanf(FILE* _Nonnull __fp, const char* _Nonnull __fmt, ...) __scanflike(2, 3);
size_t fwrite(const void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp);
__nodiscard int getc(FILE* _Nonnull __fp);
__nodiscard int getchar(void);
ssize_t getdelim(char* _Nullable * _Nonnull __line_ptr, size_t* _Nonnull __line_length_ptr, int __delimiter, FILE* _Nonnull __fp);
ssize_t getline(char* _Nullable * _Nonnull __line_ptr, size_t* _Nonnull __line_length_ptr, FILE* _Nonnull __fp);

void perror(const char* _Nullable __msg);
int printf(const char* _Nonnull __fmt, ...) __printflike(1, 2);
int putc(int __ch, FILE* _Nonnull __fp);
int putchar(int __ch);
int puts(const char* _Nonnull __s);
int remove(const char* _Nonnull __path);
void rewind(FILE* _Nonnull __fp);
int scanf(const char* _Nonnull __fmt, ...) __scanflike(1, 2);
void setbuf(FILE* _Nonnull __fp, char* _Nullable __buf);
int setvbuf(FILE* _Nonnull __fp, char* _Nullable __buf, int __mode, size_t __size);
int sscanf(const char* _Nonnull __s, const char* _Nonnull __fmt, ...) __scanflike(2, 3);
int ungetc(int __ch, FILE* _Nonnull __fp);
int vfprintf(FILE* _Nonnull __fp, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);
int vprintf(const char* _Nonnull __fp, va_list __args) __printflike(1, 0);

int dprintf(int __fd, const char* _Nonnull __fmt, ...) __printflike(2, 3);
int vdprintf(int __fd, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);

#if (defined(__STDC_VERSION__) && __STDC_VERSION__ < 201112L) || \
    (defined(__cplusplus) && __cplusplus <= 201103L)
char* _Nullable gets(char* _Nonnull __buf) __attribute__((__deprecated__("gets is unsafe, use fgets instead")));
#endif
int sprintf(char* __BIONIC_COMPLICATED_NULLNESS __s, const char* _Nonnull __fmt, ...)
    __printflike(2, 3) __warnattr_strict("sprintf is often misused; please use snprintf");
int vsprintf(char* __BIONIC_COMPLICATED_NULLNESS __s, const char* _Nonnull __fmt, va_list __args)
    __printflike(2, 0) __warnattr_strict("vsprintf is often misused; please use vsnprintf");
char* _Nullable tmpnam(char* _Nullable __s)
    __warnattr("tmpnam is unsafe, use mkstemp or tmpfile instead");
#define P_tmpdir "/tmp/" /* deprecated */
char* _Nullable tempnam(const char* _Nullable __dir, const char* _Nullable __prefix)
    __warnattr("tempnam is unsafe, use mkstemp or tmpfile instead");

/**
 * [rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html) changes
 * the name or location of a file.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int rename(const char* _Nonnull __old_path, const char* _Nonnull __new_path);

/**
 * [renameat(2)](https://man7.org/linux/man-pages/man2/renameat.2.html) changes
 * the name or location of a file, interpreting relative paths using an fd.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int renameat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path);

#if defined(__USE_GNU)

/**
 * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
 * to fail if the new path already exists.
 */
#define RENAME_NOREPLACE (1<<0)

/**
 * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
 * to atomically exchange the two paths.
 */
#define RENAME_EXCHANGE (1<<1)

/**
 * Flag for [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html)
 * to create a union/overlay filesystem object.
 */
#define RENAME_WHITEOUT (1<<2)

/**
 * [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html) changes
 * the name or location of a file, interpreting relative paths using an fd,
 * with optional `RENAME_` flags.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(30)
int renameat2(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path, unsigned __flags) __INTRODUCED_IN(30);
#endif /* __BIONIC_AVAILABILITY_GUARD(30) */


#endif

int fseek(FILE* _Nonnull __fp, long __offset, int __whence);
__nodiscard long ftell(FILE* _Nonnull __fp);

/* See https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md */
#if defined(__USE_FILE_OFFSET64)

#if __BIONIC_AVAILABILITY_GUARD(24)
int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos) __RENAME(fgetpos64) __INTRODUCED_IN(24);
int fsetpos(FILE* _Nonnull __fp, const fpos_t* _Nonnull __pos) __RENAME(fsetpos64) __INTRODUCED_IN(24);
int fseeko(FILE* _Nonnull __fp, off_t __offset, int __whence) __RENAME(fseeko64) __INTRODUCED_IN(24);
__nodiscard off_t ftello(FILE* _Nonnull __fp) __RENAME(ftello64) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

#  if defined(__USE_BSD)
/* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */

#if __BIONIC_AVAILABILITY_GUARD(24)
__nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
              int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
              int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
              fpos_t (* _Nullable __seek_fn)(void* _Nonnull, fpos_t, int),
              int (* _Nullable __close_fn)(void* _Nonnull)) __RENAME(funopen64) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

#  endif
#else
int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos);
int fsetpos(FILE* _Nonnull __fp, const fpos_t* _Nonnull __pos);
int fseeko(FILE* _Nonnull __fp, off_t __offset, int __whence);
__nodiscard off_t ftello(FILE* _Nonnull __fp);
#  if defined(__USE_BSD)
/* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
__nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
              int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
              int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
              fpos_t (* _Nullable __seek_fn)(void* _Nonnull, fpos_t, int),
              int (* _Nullable __close_fn)(void* _Nonnull));
#  endif
#endif

#if __BIONIC_AVAILABILITY_GUARD(24)
int fgetpos64(FILE* _Nonnull __fp, fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
int fsetpos64(FILE* _Nonnull __fp, const fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
int fseeko64(FILE* _Nonnull __fp, off64_t __offset, int __whence) __INTRODUCED_IN(24);
__nodiscard off64_t ftello64(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

#if defined(__USE_BSD)
/* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */

#if __BIONIC_AVAILABILITY_GUARD(24)
__nodiscard FILE* _Nullable funopen64(const void* _Nullable __cookie,
                int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
                int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
                fpos64_t (* _Nullable __seek_fn)(void* _Nonnull, fpos64_t, int),
                int (* _Nullable __close_fn)(void* _Nonnull)) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

#endif

__nodiscard FILE* _Nullable fopen(const char* _Nonnull __path, const char* _Nonnull __mode);

#if __BIONIC_AVAILABILITY_GUARD(24)
__nodiscard FILE* _Nullable fopen64(const char* _Nonnull __path, const char* _Nonnull __mode) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

FILE* _Nullable freopen(const char* _Nullable __path, const char* _Nonnull __mode, FILE* _Nonnull __fp);

#if __BIONIC_AVAILABILITY_GUARD(24)
FILE* _Nullable freopen64(const char* _Nullable __path, const char* _Nonnull __mode, FILE* _Nonnull __fp) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

__nodiscard FILE* _Nullable tmpfile(void);

#if __BIONIC_AVAILABILITY_GUARD(24)
__nodiscard FILE* _Nullable tmpfile64(void) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


int snprintf(char* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __size, const char* _Nonnull __fmt, ...) __printflike(3, 4);
int vfscanf(FILE* _Nonnull __fp, const char* _Nonnull __fmt, va_list __args) __scanflike(2, 0);
int vscanf(const char* _Nonnull __fmt , va_list __args) __scanflike(1, 0);
int vsnprintf(char* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __size, const char* _Nonnull __fmt, va_list __args) __printflike(3, 0);
int vsscanf(const char* _Nonnull __s, const char* _Nonnull __fmt, va_list __args) __scanflike(2, 0);

#define L_ctermid 1024 /* size for ctermid() */

#if __BIONIC_AVAILABILITY_GUARD(26)
char* _Nonnull ctermid(char* _Nullable __buf) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


__nodiscard FILE* _Nullable fdopen(int __fd, const char* _Nonnull __mode);
__nodiscard int fileno(FILE* _Nonnull __fp);
int pclose(FILE* _Nonnull __fp);
__nodiscard FILE* _Nullable popen(const char* _Nonnull __command, const char* _Nonnull __mode);
void flockfile(FILE* _Nonnull  __fp);
int ftrylockfile(FILE* _Nonnull __fp);
void funlockfile(FILE* _Nonnull __fp);
__nodiscard int getc_unlocked(FILE* _Nonnull __fp);
__nodiscard int getchar_unlocked(void);
int putc_unlocked(int __ch, FILE* _Nonnull __fp);
int putchar_unlocked(int __ch);


#if __BIONIC_AVAILABILITY_GUARD(23)
__nodiscard FILE* _Nullable fmemopen(void* _Nullable __buf, size_t __size, const char* _Nonnull __mode) __INTRODUCED_IN(23);
__nodiscard FILE* _Nullable open_memstream(char* _Nonnull * _Nonnull __ptr, size_t* _Nonnull __size_ptr) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
int  asprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, ...) __printflike(2, 3);
char* _Nullable fgetln(FILE* _Nonnull __fp, size_t* _Nonnull __length_ptr);
int fpurge(FILE* _Nonnull __fp);
void setbuffer(FILE* _Nonnull __fp, char* _Nullable __buf, int __size);
int setlinebuf(FILE* _Nonnull __fp);
int vasprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);

#if __BIONIC_AVAILABILITY_GUARD(23)
void clearerr_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
__nodiscard int feof_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
__nodiscard int ferror_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(24)
__nodiscard int fileno_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

#define fropen(cookie, fn) funopen(cookie, fn, 0, 0, 0)
#define fwopen(cookie, fn) funopen(cookie, 0, fn, 0, 0)
#endif

#if defined(__USE_BSD)

#if __BIONIC_AVAILABILITY_GUARD(28)
int fflush_unlocked(FILE* _Nullable __fp) __INTRODUCED_IN(28);
__nodiscard int fgetc_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
int fputc_unlocked(int __ch, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
size_t fread_unlocked(void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
size_t fwrite_unlocked(const void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

#endif

#if defined(__USE_GNU)

#if __BIONIC_AVAILABILITY_GUARD(28)
int fputs_unlocked(const char* _Nonnull __s, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
char* _Nullable fgets_unlocked(char* _Nonnull __buf, int __size, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

#endif

#if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
#include <bits/fortify/stdio.h>
#endif

__END_DECLS

#endif
```