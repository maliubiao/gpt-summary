Response:
Let's break down the thought process for analyzing the `hexnan.c` code.

1. **Understanding the Goal:** The request is to analyze the given C code, specifically `hexnan.c` from Android's Bionic libc. The goal is to understand its functionality, its relation to Android, internal implementation details, potential usage errors, and how it's reached from higher levels.

2. **Initial Code Scan and Keyword Identification:**  First, I'd quickly scan the code, looking for keywords and patterns. I see:
    * `#include "gdtoaimp.h"`: This suggests it's part of a larger library for converting between strings and floating-point numbers. "gdtoa" likely stands for "string to floating-point".
    * `static void L_shift(...)`: A local helper function for left-shifting.
    * `int hexnan(...)`: The main function, named `hexnan`, which strongly suggests handling hexadecimal representations of NaN (Not a Number).
    * `ULong`:  Unsigned long, implying manipulation of raw bit patterns.
    * `FPI`:  Likely a structure representing floating-point information (precision, etc.).
    * `hexdig`:  An array, presumably mapping hexadecimal characters to their numerical values.
    * `STRTOG_NaN`, `STRTOG_NaNbits`: Constants indicating different NaN states, hinting at return values related to string conversion.
    * Loops and bitwise operations (`<<`, `>>`, `&`, `|`):  Indicate low-level manipulation of the input.

3. **Deciphering the Functionality:**  The function name `hexnan` and the constants `STRTOG_NaN` and `STRTOG_NaNbits` strongly suggest the core functionality:  parsing a hexadecimal string representation of a NaN value and storing its bit pattern. The presence of `FPI` suggests it needs information about the target floating-point format.

4. **Detailed Code Analysis (Step-by-Step for `hexnan`):**

   * **Initialization:**
      * Checks if `hexdig` is initialized and initializes it if not. This is a common pattern for lazy initialization.
      * Calculates the number of `ULong`s needed to store the NaN's bit pattern based on `fpi->nbits`.
      * Initializes the `ULong` array `x0` to zero.

   * **Parsing the Input String:**
      * Skips leading whitespace.
      * Handles the optional "0x" or "0X" prefix.
      * Iterates through the string, character by character.
      * Uses the `hexdig` array to convert hexadecimal characters to their numerical values.
      * Accumulates the hexadecimal digits into `ULong` values. The `L_shift` function is used to handle accumulating digits when a space or the end of the hexadecimal value is encountered. This indicates handling of potentially long hexadecimal strings with spaces as separators.

   * **Handling Spaces and Parentheses:** The code seems to allow spaces within the hexadecimal representation as separators. The closing parenthesis `)` acts as a terminator. The `#ifndef GDTOA_NON_PEDANTIC_NANCHECK` section suggests a stricter mode where parentheses might not be allowed.

   * **Error Handling:** If an invalid hexadecimal character is found (not a digit or a-f/A-F), and it's not a space or closing parenthesis in the lenient mode, it returns `STRTOG_NaN`.

   * **Post-Processing:**
      * Handles any remaining digits after the last space or parenthesis.
      * Shifts the accumulated bits to the correct position using `L_shift`.
      * Copies the parsed bit pattern into the `x0` array.
      * Truncates the high-order word if necessary to fit the target floating-point precision.
      * Ensures the NaN is not a "quiet NaN" with all mantissa bits zero, setting the least significant bit if it is.

5. **Analyzing `L_shift`:** This function performs a left shift operation on an array of `ULong` values, simulating a large integer shift. It shifts bits from the higher `ULong` to the lower `ULong`.

6. **Connecting to Android:**
   * **libc:**  The code resides in `bionic/libc`, so it's a fundamental part of Android's C library.
   * **Math Library:** It's in the `gdtoa` directory, which is clearly related to string-to-floating-point conversion, a key part of math libraries.
   * **NDK:**  NDK applications that need to parse floating-point numbers from strings might indirectly use this function.

7. **Dynamic Linker (Initial Thought - then Correction):** My initial thought might be that this specific file directly involves the dynamic linker. However, after closer inspection, the code itself doesn't seem to have direct calls to dynamic linker functions (like `dlopen`, `dlsym`, etc.). The *library* this file belongs to (libc) is obviously linked by the dynamic linker. Therefore, the connection is *indirect*. I need to explain *how* libc is linked and how functions within it are used.

8. **Usage Errors:**  Consider common mistakes:
    * Incorrect hexadecimal format (missing '0x', invalid characters).
    * Providing a hexadecimal string that doesn't represent a valid NaN (though the function is specifically for NaNs, the format still needs to be correct).
    * Assuming a specific NaN representation will always be parsed identically across different architectures or floating-point formats.

9. **Tracing from Android Framework/NDK:**  Think about how string-to-float conversion happens in Android:
    * **Java:**  Methods like `Float.parseFloat()` or `Double.parseDouble()` are common. These eventually call native methods.
    * **NDK:** Functions like `strtof`, `strtod`, or potentially custom parsing logic.
    * **libc:**  These Java native methods and NDK functions will likely call the standard C library functions for string-to-float conversion, which in turn might use `hexnan` when a NaN is detected in hexadecimal format.

10. **Frida Hooking:**  Think about where to place hooks to observe this function:
    * Directly hooking `hexnan`:  The most direct approach.
    * Hooking higher-level functions like `strtod`: To see when `hexnan` is called indirectly.

11. **Structuring the Output:** Organize the information logically with clear headings: Functionality, Android Relationship, Implementation Details, Dynamic Linker, Logic Reasoning, Common Errors, and Tracing/Hooking. Use code blocks for examples and snippets.

12. **Refinement and Review:**  Read through the generated explanation, ensuring clarity, accuracy, and completeness. Correct any misconceptions (like my initial overemphasis on the direct dynamic linker involvement). Add details where needed and remove redundancy. Ensure the language is precise and easy to understand. For instance, elaborating on the purpose of the `FPI` struct makes the explanation more informative. Double-checking the assumptions in the logical reasoning section is also important.
## 分析 Android Bionic 中 hexnan.c 的源代码

这个 `hexnan.c` 文件是 Android Bionic libc 库中 `gdtoa`（string to floating-point conversion）组件的一部分。它的主要功能是 **将一个表示十六进制 NaN (Not a Number) 值的字符串转换为其二进制表示**。

**功能列举:**

1. **解析十六进制 NaN 字符串:**  `hexnan` 函数接收一个指向字符串的指针 `sp`，并尝试从该字符串中解析出十六进制格式的 NaN 值。它能处理可选的 "0x" 或 "0X" 前缀，并且允许在十六进制数字之间存在空格作为分隔符。
2. **提取 NaN 的 payload (有效载荷):**  对于 NaN 值，其二进制表示中除了特定的 exponent 位模式外，还包含一个 payload，用于区分不同的 NaN 值（也称为 signaling NaN 和 quiet NaN）。`hexnan` 函数负责提取这个 payload。
3. **根据 FPI (Floating Point Information) 结构处理不同浮点数精度:**  `hexnan` 函数接收一个 `FPI` 结构的指针 `fpi`，该结构包含了目标浮点数的精度信息（例如，多少位有效位）。这使得 `hexnan` 可以处理不同精度的 NaN 值，例如单精度浮点数 (float) 和双精度浮点数 (double)。
4. **将十六进制数字转换为二进制表示:**  函数内部使用 `hexdig` 数组将十六进制字符 ('0'-'9', 'a'-'f', 'A'-'F') 转换为对应的数值。
5. **进行位移操作:**  使用 `L_shift` 静态函数进行位移操作，将解析出的十六进制数字组合成最终的二进制 NaN 表示。
6. **处理空格分隔符:** 允许十六进制 NaN 字符串中存在空格作为分隔符，方便用户输入或表示较长的 NaN 值。
7. **返回状态码:**  根据解析结果，`hexnan` 函数返回不同的状态码，例如 `STRTOG_NaN` 表示解析失败（不是一个有效的十六进制 NaN），`STRTOG_NaNbits` 表示成功解析出了 NaN 的位模式。

**与 Android 功能的关系及举例说明:**

`hexnan.c` 是 Android libc 的一部分，因此直接为 Android 系统的底层功能提供支持。它主要用于以下场景：

* **字符串到浮点数的转换:**  Android 的 Java 层或 NDK 中的 C/C++ 代码在需要将字符串转换为浮点数时，可能会间接地使用到这个函数。例如，当解析包含 "NaN" 或十六进制 NaN 表示的字符串时。
* **数学库函数:**  `gdtoa` 组件本身就是为了提供字符串到浮点数的转换功能，因此 `hexnan` 自然会被相关的数学库函数（如 `strtod`, `strtof` 等）调用。
* **配置文件解析:**  某些 Android 组件或应用程序可能需要解析包含浮点数或特殊浮点数值（如 NaN）的配置文件。
* **调试和测试:**  开发者可能需要手动构造或解析 NaN 值进行调试或测试浮点数相关的代码。

**举例说明:**

假设一个 Android 应用程序需要解析一个包含浮点数的字符串，其中一个值表示为十六进制 NaN：

```java
String nanString = "0x7ff8000000000000"; // 双精度 quiet NaN 的一种表示
double nanValue = Double.parseDouble(nanString);
System.out.println(nanValue); // 输出 NaN
```

在这个过程中，`Double.parseDouble()` 底层会调用到 Android libc 中的 `strtod` 函数。如果 `strtod` 识别到输入的字符串类似于 "0x..." 的十六进制格式，并且符合 NaN 的模式，它可能会调用 `hexnan` 函数来解析这个十六进制 NaN 字符串并将其转换为对应的双精度浮点数 NaN 的二进制表示。

**详细解释 libc 函数的实现:**

**`hexnan(CONST char **sp, FPI *fpi, ULong *x0)`:**

1. **初始化:**
   - 检查 `hexdig` 数组是否已初始化，如果未初始化则调用 `__hexdig_init_D2A()` 进行初始化。`hexdig` 数组用于快速查找十六进制字符对应的数值。
   - 根据 `fpi->nbits` (目标浮点数的总位数) 计算需要多少个 `ULong` (无符号长整型) 来存储 NaN 的位模式，并初始化存储结果的数组 `x0`。

2. **跳过前导空格和可选的 "0x" 前缀:**
   - 循环跳过输入字符串 `s` 中的前导空格。
   - 检查字符串是否以 "0x" 或 "0X" 开头，如果是则跳过这两个字符。

3. **解析十六进制数字:**
   - 循环遍历字符串 `s` 中的字符。
   - 使用 `hexdig[c]` 获取当前字符 `c` 对应的数值 `h`。
   - **处理有效的十六进制数字:**
     - 如果 `h` 非零，表示当前字符是有效的十六进制数字。
     - 将 `h` 的低 4 位与当前 `ULong` 元素 `*x` 进行组合，逐步构建 NaN 的位模式。
     - 使用变量 `i` 跟踪当前 `ULong` 元素中已填充的位数，当 `i` 达到 8 (表示一个 `ULong` 的 32 位被填满) 时，移动到下一个 `ULong` 元素。
   - **处理空格分隔符:**
     - 如果遇到空格，并且之前已经解析到过十六进制数字 (`havedig > 0`)，则认为这是一个分隔符。
     - 如果当前 `ULong` 元素还有剩余空间 (`i < 8`)，则将已解析的位左移 (`L_shift`) 到高位。
     - 重置状态，准备解析下一段十六进制数字。
   - **处理右括号 `)`:**
     - 如果遇到右括号 `)` 并且之前已经解析到过十六进制数字，则认为 NaN 值解析结束，更新输入字符串指针 `*sp` 并跳出循环。
   - **错误处理:**
     - 如果遇到既不是有效的十六进制数字，也不是空格或右括号的字符，则返回 `STRTOG_NaN` 表示解析失败。

4. **处理结尾的十六进制数字:**
   - 如果循环结束后还有剩余的已解析十六进制数字，则将其左移到正确的位置。

5. **将解析结果存储到 `x0` 数组:**
   - 将解析出的 NaN 位模式从临时存储位置 `x` 拷贝到 `x0` 数组中。

6. **处理精度问题:**
   - 如果目标浮点数的精度小于一个 `ULong` 的位数，则需要截断高位。

7. **确保结果是一个 NaN:**
   - 检查解析出的位模式，如果所有位都是零，则将其设置为一个默认的 quiet NaN 值 (将最低位设置为 1)。

8. **返回状态码:**
   - 返回 `STRTOG_NaNbits` 表示成功解析出了 NaN 的位模式。

**`static void L_shift(ULong *x, ULong *x1, int i)`:**

这个静态函数用于将一个 `ULong` 数组表示的大整数向左移动 `i` 位。

1. **计算位移量:**  `i` 是以字节为单位的位移量，将其转换为以位为单位的位移量 `j = ULbits - (8 - i) << 2;`，其中 `ULbits` 是 `ULong` 的位数。

2. **循环进行位移:**
   - 从数组的低地址向高地址遍历 `ULong` 元素。
   - 对于每个元素 `*x`，从下一个元素 `x[1]` 中取出高 `j` 位，与当前元素进行或运算 (`*x |= x[1] << j`)。
   - 将下一个元素 `x[1]` 右移 `i` 位 (`x[1] >>= i`)，将低位移出。

**涉及 dynamic linker 的功能:**

`hexnan.c` 自身并不直接涉及 dynamic linker 的功能。然而，作为 Android libc 的一部分，它会被动态链接器加载到进程的地址空间中。

**so 布局样本 (libc.so 的部分布局):**

```
Address Range     Permissions     Mapping
-----------------------------------------------------
...
0xb7000000-0xb71fffff r-x p  b7000000 /system/lib/libc.so  // 代码段
0xb71ff000-0xb7200fff r-- p  b71ff000 /system/lib/libc.so  // 只读数据段
0xb7200000-0xb720efff rw- p  b7200000 /system/lib/libc.so  // 可读写数据段 (例如全局变量)
...
```

在这个布局中，`hexnan` 函数的代码会位于 `r-x` (可读可执行) 代码段的某个地址范围内。

**链接的处理过程:**

1. **编译:**  `hexnan.c` 被编译成目标文件 (`.o`)。
2. **链接:**  链接器 (linker) 将 `hexnan.o` 和其他 libc 的目标文件链接在一起，生成最终的动态链接库 `libc.so`。链接器会解析符号引用，例如 `hexnan` 中可能用到的其他 libc 函数或者全局变量。
3. **加载:**  当 Android 进程启动时，动态链接器 (e.g., `linker64`) 会负责加载 `libc.so` 到进程的地址空间中。
4. **符号解析:**  动态链接器会解析 `libc.so` 中导出的符号，例如 `hexnan`，使得其他共享库或可执行文件可以通过符号名找到并调用这个函数。

**逻辑推理 (假设输入与输出):**

**假设输入:**

```c
const char *nan_str = "0x1.fffffffffffffp+1023"; // 双精度正无穷大 (不是 NaN，但可以测试解析逻辑)
FPI fpi_double = { .nbits = 64, .rounding = 0 }; // 假设双精度浮点数
ULong result[2];
const char *ptr = nan_str;
```

**预期输出:**

由于输入的是无穷大而不是 NaN，`hexnan` 函数应该返回 `STRTOG_NaN`，并且 `result` 数组的内容不会被修改或包含有效的 NaN 位模式。实际上，`hexnan` 主要是针对 NaN 的解析，对于无穷大等其他特殊值，会有其他的处理逻辑。

**假设输入 (真正的 NaN):**

```c
const char *nan_str = "0x7ff8000000000001"; // 双精度 quiet NaN
FPI fpi_double = { .nbits = 64, .rounding = 0 };
ULong result[2];
const char *ptr = nan_str;
```

**预期输出:**

`hexnan` 函数应该成功解析出 NaN 的位模式，并将其存储到 `result` 数组中。返回值应该是 `STRTOG_NaNbits`。 `result` 数组的内容将是表示该 NaN 值的两个 `ULong`。

**用户或编程常见的使用错误:**

1. **提供无效的十六进制格式:**
   - 缺少 "0x" 前缀 (如果期望有前缀)。
   - 包含无效的十六进制字符 (例如 'g')。
   - 数字之间没有空格分隔符 (如果字符串很长)。
2. **误以为可以解析所有浮点数特殊值:**  `hexnan` 专门用于解析十六进制 NaN 值，不能用于解析无穷大、零等其他浮点数特殊值。
3. **不理解 NaN 的 payload:**  可能不清楚 NaN 的高位模式和 payload 的含义，导致解析出的值不符合预期。
4. **精度不匹配:**  提供的十六进制字符串的位数与目标浮点数的精度不匹配，可能导致截断或错误解析。

**示例 (提供无效的十六进制格式):**

```c
const char *invalid_nan_str = "7ff800000000000a"; // 缺少 "0x"
FPI fpi_double = { .nbits = 64, .rounding = 0 };
ULong result[2];
const char *ptr = invalid_nan_str;
int status = hexnan(&ptr, &fpi_double, result);
// status 很可能为 STRTOG_NaN
```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `hexnan` 的路径 (示例):**

1. **Java 代码:** Android Framework 中的 Java 代码 (例如，在解析配置文件或处理用户输入时) 可能需要将字符串转换为 `double` 或 `float`。
   ```java
   String nanStr = "0x7ff8000000000000";
   double value = Double.parseDouble(nanStr);
   ```
2. **`Double.parseDouble()`:** `Double.parseDouble()` 是 Java 标准库中的方法，用于将字符串解析为 `double` 类型。
3. **Native 方法调用:** `Double.parseDouble()` 最终会调用到 JVM 中的 native 方法。
4. **`libcore` 库:** 这些 native 方法通常位于 `libcore` 库中。
5. **`strtod` 函数:** `libcore` 中的相关代码会调用到 Android Bionic libc 提供的 `strtod` 函数 (或类似的字符串到浮点数转换函数)。
6. **`gdtoa` 组件:** `strtod` 函数会使用 `gdtoa` 组件来进行实际的转换工作。
7. **`hexnan` 函数:** 当 `strtod` 检测到输入的字符串是十六进制格式的 NaN 值时，它会调用 `hexnan` 函数进行解析。

**NDK 到 `hexnan` 的路径:**

1. **NDK C/C++ 代码:** NDK 开发的应用可以直接使用 C/C++ 标准库函数进行字符串到浮点数的转换。
   ```c++
   #include <cstdlib>
   double value = std::strtod("0x7ff8000000000000", nullptr);
   ```
2. **`std::strtod`:** `std::strtod` 是 C++ 标准库中的函数，它通常会调用底层的 C 库函数 `strtod`。
3. **Android Bionic libc:**  在 Android 环境下，`std::strtod` 会调用 Android Bionic libc 提供的 `strtod` 函数。
4. **`gdtoa` 组件和 `hexnan`:** 后续的调用路径与 Android Framework 的情况类似，最终会到达 `hexnan` 函数。

**Frida Hook 示例:**

可以使用 Frida hook `hexnan` 函数来观察其调用和参数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(['com.example.myapp']) # 替换为你的应用包名
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName("libc.so", "hexnan"), {
            onEnter: function(args) {
                console.log("[*] Called hexnan");
                console.log("[*] sp: " + ptr(args[0]).readCString());
                console.log("[*] fpi: " + args[1]);
                console.log("[*] x0: " + args[2]);
            },
            onLeave: function(retval) {
                console.log("[*] hexnan returned: " + retval);
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    if not pid:
        device.resume(session.pid)
    input("Press Enter to detach...\n")
    session.detach()
except frida.ProcessNotFoundError:
    print("进程未找到，请提供正确的进程 ID 或应用包名。")
except Exception as e:
    print(e)
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_hexnan.py`。
2. 找到目标 Android 应用的进程 ID (PID)。
3. 运行 Frida 脚本：`python hook_hexnan.py <PID>` 或 `python hook_hexnan.py com.example.myapp`。
4. 在应用中触发会调用 `hexnan` 的操作 (例如，解析包含十六进制 NaN 的字符串)。
5. Frida 会打印出 `hexnan` 函数被调用时的参数和返回值。

这个 Frida 脚本会 hook `libc.so` 中的 `hexnan` 函数，并在函数调用前后打印相关信息，帮助你调试和理解其工作流程。你需要将 `<PID>` 替换为目标应用的进程 ID，或者将 `com.example.myapp` 替换为应用的包名。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/hexnan.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/****************************************************************

The author of this software is David M. Gay.

Copyright (C) 2000 by Lucent Technologies
All Rights Reserved

Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby
granted, provided that the above copyright notice appear in all
copies and that both that the copyright notice and this
permission notice and warranty disclaimer appear in supporting
documentation, and that the name of Lucent or any of its entities
not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

****************************************************************/

/* Please send bug reports to David M. Gay (dmg at acm dot org,
 * with " at " changed at "@" and " dot " changed to ".").	*/

#include "gdtoaimp.h"

 static void
#ifdef KR_headers
L_shift(x, x1, i) ULong *x; ULong *x1; int i;
#else
L_shift(ULong *x, ULong *x1, int i)
#endif
{
	int j;

	i = 8 - i;
	i <<= 2;
	j = ULbits - i;
	do {
		*x |= x[1] << j;
		x[1] >>= i;
		} while(++x < x1);
	}

 int
#ifdef KR_headers
hexnan(sp, fpi, x0)
	CONST char **sp; FPI *fpi; ULong *x0;
#else
hexnan( CONST char **sp, FPI *fpi, ULong *x0)
#endif
{
	ULong c, h, *x, *x1, *xe;
	CONST char *s;
	int havedig, hd0, i, nbits;

	if (!hexdig['0'])
		__hexdig_init_D2A();
	nbits = fpi->nbits;
	x = x0 + (nbits >> kshift);
	if (nbits & kmask)
		x++;
	*--x = 0;
	x1 = xe = x;
	havedig = hd0 = i = 0;
	s = *sp;
	/* allow optional initial 0x or 0X */
	while((c = *(CONST unsigned char*)(s+1)) && c <= ' ')
		++s;
	if (s[1] == '0' && (s[2] == 'x' || s[2] == 'X')
	 && *(CONST unsigned char*)(s+3) > ' ')
		s += 2;
	while((c = *(CONST unsigned char*)++s)) {
		if (!(h = hexdig[c])) {
			if (c <= ' ') {
				if (hd0 < havedig) {
					if (x < x1 && i < 8)
						L_shift(x, x1, i);
					if (x <= x0) {
						i = 8;
						continue;
						}
					hd0 = havedig;
					*--x = 0;
					x1 = x;
					i = 0;
					}
				while(*(CONST unsigned char*)(s+1) <= ' ')
					++s;
				if (s[1] == '0' && (s[2] == 'x' || s[2] == 'X')
				 && *(CONST unsigned char*)(s+3) > ' ')
					s += 2;
				continue;
				}
			if (/*(*/ c == ')' && havedig) {
				*sp = s + 1;
				break;
				}
#ifndef GDTOA_NON_PEDANTIC_NANCHECK
			do {
				if (/*(*/ c == ')') {
					*sp = s + 1;
					break;
					}
				} while((c = *++s));
#endif
			return STRTOG_NaN;
			}
		havedig++;
		if (++i > 8) {
			if (x <= x0)
				continue;
			i = 1;
			*--x = 0;
			}
		*x = (*x << 4) | (h & 0xf);
		}
	if (!havedig)
		return STRTOG_NaN;
	if (x < x1 && i < 8)
		L_shift(x, x1, i);
	if (x > x0) {
		x1 = x0;
		do *x1++ = *x++;
			while(x <= xe);
		do *x1++ = 0;
			while(x1 <= xe);
		}
	else {
		/* truncate high-order word if necessary */
		if ( (i = nbits & (ULbits-1)) !=0)
			*xe &= ((ULong)0xffffffff) >> (ULbits - i);
		}
	for(x1 = xe;; --x1) {
		if (*x1 != 0)
			break;
		if (x1 == x0) {
			*x1 = 1;
			break;
			}
		}
	return STRTOG_NaNbits;
	}
```