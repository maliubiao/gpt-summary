Response:
Let's break down the thought process for analyzing this `assertions.h` file.

1. **Understanding the Core Purpose:** The filename and the content immediately suggest this file deals with assertions. Assertions are a programming construct used to verify assumptions during development. If an assertion fails, it indicates a bug.

2. **Initial Code Scan for Key Elements:**  A quick scan reveals:
    * **Header Guards:** `#ifndef ASSERTIONS_H`, `#define ASSERTIONS_H 1`, `#endif`. Standard practice to prevent multiple inclusions.
    * **Copyright Notices:**  Indicates the origin (NetBSD, ISC) and licensing. While relevant for attribution, it's less critical for understanding functionality.
    * **`assertion_type` enum:** Defines the different types of assertions. This is a key element for understanding the different intent behind assertions.
    * **`assertion_failure_callback` typedef:** Declares a function pointer type for handling assertion failures. This hints at a mechanism for customizing the failure behavior.
    * **`__assertion_failed` extern variable:**  The actual callback function. Declared `extern`, meaning it's defined elsewhere.
    * **`set_assertion_failure_callback` function:** Allows setting a custom failure handler.
    * **`assertion_type_to_text` function:**  A utility for converting the enum to a human-readable string.
    * **Conditional Compilation Macros:**  `CHECK_ALL`, `__COVERITY__`, `CHECK_NONE`, `_DIAGNOSTIC`. These control which assertions are active during compilation. This is crucial for understanding how assertions are enabled/disabled in different builds.
    * **Assertion Macros (`REQUIRE`, `ENSURE`, `INSIST`, `INVARIANT`):**  These are the core macros that developers use to add assertions to their code. The expansion logic using `||` and the call to `__assertion_failed` is important.
    * **`REQUIRE_ERR`, `ENSURE_ERR`, `INSIST_ERR`, `INVARIANT_ERR`:**  Similar to the non-`_ERR` versions, but the `__assertion_failed` call passes `1` as an argument. This suggests a potential way to differentiate error severity or handling.
    * **Empty Definitions (when checks are disabled):**  When the `CHECK_*` macros are 0, the assertion macros are defined as `((void) (cond))`, effectively doing nothing.

3. **Functionality Breakdown (and answering the prompt's first request):** Based on the identified elements:
    * **Defining Assertion Types:** The `assertion_type` enum provides semantic meaning to assertions (preconditions, postconditions, internal checks, invariants).
    * **Registering a Failure Handler:** `set_assertion_failure_callback` allows customizing what happens when an assertion fails.
    * **Converting Assertion Type to Text:** `assertion_type_to_text` is a utility for reporting.
    * **Conditional Assertion Compilation:** The `CHECK_*` macros allow enabling/disabling assertions at compile time, useful for debugging vs. release builds.
    * **Assertion Macros:** The core functionality for adding assertions to code. They evaluate a condition and call the failure handler if the condition is false.

4. **Relating to Android (answering the prompt's second request):**
    * **Bionic Context:** The file's location within Bionic immediately signals its relevance to Android's core libraries.
    * **Debugging Aid:** Assertions are a fundamental debugging tool. They help developers catch errors early in the development process within Bionic itself.
    * **Example:**  Imagine a function in Bionic that calculates a square root. A `REQUIRE` assertion could be used to ensure the input is non-negative. This protects against unexpected behavior.

5. **Detailed Explanation of Libc Functions (answering the prompt's third request):**
    * **No Standard Libc Functions *Defined Here*:**  Crucially, this header file *declares* and *defines macros*. The *implementation* of the failure handling (the `__assertion_failed` function) is *not* in this file. This is a key distinction. Therefore, the focus should be on the *purpose* of the elements within this header.
    * **Focus on the Macros:** Explain how the macros expand, the role of the conditional compilation, and the purpose of the `__assertion_failed` call.

6. **Dynamic Linker (answering the prompt's fourth request):**
    * **No Direct Linker Interaction:** This header file itself doesn't directly interact with the dynamic linker. It's about compile-time and runtime checks *within* linked code.
    * **Indirect Relationship:**  The code using these assertions *is* part of Bionic, which is linked by the dynamic linker. So, the *code using assertions* will reside in memory locations determined by the linker.
    * **Example (Conceptual):** Show a simplified `.so` layout and point out where functions using these assertion macros might reside. The linking process wouldn't treat assertions specially; they are just regular code.

7. **Logic Reasoning and Input/Output (answering the prompt's fifth request):**
    * **Focus on Macro Behavior:** The logic is within the macros. Demonstrate how the macros behave with different input conditions (true/false). Show how the `__assertion_failed` function is called when the condition is false.

8. **Common Usage Errors (answering the prompt's sixth request):**
    * **Over-reliance in Release Builds:**  Leaving expensive assertions enabled in release builds can impact performance.
    * **Incorrect Conditions:**  Writing assertions that don't accurately reflect the intended state.
    * **Side Effects in Assertions:**  Assertions should not have side effects, as they might be disabled in release builds, leading to different behavior.

9. **Android Framework/NDK Path (answering the prompt's seventh request):**
    * **Deep Dive Needed:** This requires understanding Android's build system and how different layers interact.
    * **General Path:**  NDK code -> Bionic libraries (using these assertions) -> potentially triggered by framework calls.
    * **Example Scenario:**  A framework component might call a Bionic function (e.g., related to file I/O) which internally uses assertions to validate its parameters.

10. **Frida Hooking (answering the prompt's eighth request):**
    * **Target the Callback:** The most direct way to observe assertions is to hook the `__assertion_failed` function.
    * **Example Script:** Provide a basic Frida script that intercepts `__assertion_failed`, logs the arguments, and allows the program to continue or be interrupted.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should explain the `__FILE__` and `__LINE__` macros. *Correction:* While important, focusing on the core functionality of the assertion mechanism is more crucial initially. These details can be added if needed.
* **Initial thought:**  Let me explain the intricacies of the C preprocessor. *Correction:*  Keep the explanation focused on how the macros work in this specific context. Avoid unnecessary digressions.
* **Realization:** The prompt asks for "libc function implementations." This header *doesn't* implement libc functions in the traditional sense. It provides *infrastructure* for assertions. Adjust the explanation accordingly.
* **Emphasis:**  Highlight the conditional compilation aspect as it's key to understanding how assertions are used in different build scenarios.

By following this structured approach, breaking down the problem, and iteratively refining the understanding, one can arrive at a comprehensive and accurate answer to the prompt.
## `bionic/libc/upstream-netbsd/lib/libc/include/isc/assertions.handroid` 源代码文件分析

这个头文件 `assertions.h` 定义了一套用于在 C 代码中进行断言检查的机制。它来源于 NetBSD 项目，并且被 Android 的 Bionic C 库所采用。断言是一种编程辅助工具，用于在开发和测试阶段验证代码中的假设。如果断言的条件为假，则表示代码中存在错误。

**功能列举:**

1. **定义断言类型 (`assertion_type`):**  定义了不同类型的断言，例如：
    * `assert_require`:  用于检查函数或代码块执行的**前置条件 (Precondition)**。  表示在执行某段代码之前必须满足的条件。
    * `assert_ensure`: 用于检查函数或代码块执行的**后置条件 (Postcondition)**。 表示在执行某段代码之后应该满足的条件。
    * `assert_insist`: 用于表示一个**永远不应该发生的情况**。 如果这个断言失败，通常意味着程序进入了一个无法恢复的错误状态。
    * `assert_invariant`: 用于检查在代码执行的特定阶段，某些**不变量 (Invariant)** 是否保持不变。例如，一个数据结构的内部状态在操作前后应该保持一致。

2. **定义断言失败回调函数类型 (`assertion_failure_callback`):** 定义了一个函数指针类型，用于指定当断言失败时要调用的回调函数。这个回调函数会接收断言失败的文件名、行号、断言类型以及断言的条件字符串等信息。

3. **声明全局断言失败回调函数指针 (`__assertion_failed`):** 声明了一个全局的函数指针，用于指向实际的断言失败处理函数。这个指针在其他地方被定义并初始化。

4. **提供设置断言失败回调函数的接口 (`set_assertion_failure_callback`):**  允许开发者自定义断言失败时的处理行为，例如，可以记录日志、打印错误信息、终止程序等。

5. **提供将断言类型转换为文本的函数 (`assertion_type_to_text`):**  提供一个实用函数，可以将 `assertion_type` 枚举值转换为可读的字符串，方便在断言失败时输出更清晰的信息。

6. **通过宏定义控制断言的启用和禁用 (`CHECK_REQUIRE`, `CHECK_ENSURE`, `CHECK_INSIST`, `CHECK_INVARIANT`):**  通过预处理宏定义，可以在编译时选择性地启用或禁用不同类型的断言。这允许在开发和调试阶段启用断言以尽早发现错误，而在发布版本中禁用断言以提高性能。
    * `CHECK_ALL`:  启用所有类型的断言。
    * `CHECK_NONE`: 禁用所有类型的断言。
    * `_DIAGNOSTIC`:  通常用于调试构建，会默认启用断言（除非显式禁用）。
    * `__COVERITY__`:  用于静态代码分析工具 Coverity，也会启用断言。

7. **定义断言宏 (`REQUIRE`, `ENSURE`, `INSIST`, `INVARIANT` 及其 `_ERR` 版本):**  提供了方便使用的宏，用于在代码中插入断言检查。
    * `宏名(cond)`:  如果 `cond` 为假（0），则调用 `__assertion_failed` 函数，并传递相关信息。
    * `宏名_ERR(cond)`:  与非 `_ERR` 版本类似，但会向 `__assertion_failed` 函数传递一个额外的错误标志 (通常为 1)。 这可能用于区分不同的错误级别或处理方式。
    * 当对应的 `CHECK_*` 宏为 0 时，这些断言宏会被定义为空操作 `((void) (cond))`，从而在编译时被优化掉，不会产生任何运行时开销。`INSIST` 宏在 `__lint__` 环境下也会被定义为空。

**与 Android 功能的关系及举例说明:**

这个头文件是 Bionic C 库的一部分，因此它直接影响着 Android 系统中所有使用 Bionic 库的组件，包括：

* **Android Framework:**  Framework 层的代码，例如 System Server、Activity Manager 等，底层都依赖于 Bionic 库提供的基础功能。
* **NDK (Native Development Kit):**  NDK 允许开发者使用 C/C++ 编写 Android 应用的原生代码。这些原生代码也会链接到 Bionic 库，并可以使用这里定义的断言机制。
* **系统服务和守护进程:**  Android 系统中许多底层的服务和守护进程都是使用 C/C++ 编写的，它们也依赖于 Bionic 库。

**举例说明:**

假设在 Android Framework 的某个组件中，有一个函数负责处理用户输入，并且假设用户输入的某个值 `userId` 必须是非负数。可以使用 `REQUIRE` 断言来检查这个前提条件：

```c
// Android Framework 代码示例
#include <isc/assertions.h>

void processUserInput(int userId, const char* data) {
    REQUIRE(userId >= 0); // 断言：userId 必须是非负数

    // ... 处理用户输入的逻辑 ...
}
```

如果在开发或测试阶段，`processUserInput` 函数被调用时 `userId` 的值是负数，那么 `REQUIRE(userId >= 0)` 断言将会失败，导致 `__assertion_failed` 函数被调用。具体的行为取决于如何配置断言失败的回调函数，通常会打印错误信息，包括文件名、行号以及断言的条件，帮助开发者快速定位问题。

**libc 函数的功能实现:**

这个 `assertions.h` 文件本身**并没有实现任何标准的 libc 函数**。它定义的是一套断言机制的接口和宏。

实际的断言失败处理函数 (`__assertion_failed`) 的实现通常位于 Bionic 库的其他源文件中 (例如，在 `bionic/libc/bionic/assertion_handler.c` 或类似的文件中)。

`__assertion_failed` 函数的典型实现可能包含以下操作：

1. **获取断言失败的信息:**  接收 `assertions.h` 中断言宏传递的文件名、行号、断言类型、条件字符串和错误标志。
2. **格式化错误消息:**  将这些信息格式化成易于阅读的错误消息。
3. **输出错误消息:**  将错误消息输出到标准错误流 (stderr) 或系统日志中。
4. **（可选）执行调试操作:**  例如，触发一个断点，以便开发者可以使用调试器进行进一步分析。
5. **（可选）终止程序:**  根据配置，断言失败也可能导致程序终止执行，以防止错误继续扩散。

`set_assertion_failure_callback` 函数的实现会修改全局函数指针 `__assertion_failed` 的值，允许开发者替换默认的断言失败处理函数。

`assertion_type_to_text` 函数的实现通常是一个简单的 `switch` 语句或查找表，将 `assertion_type` 枚举值映射到对应的字符串表示 ("require", "ensure", "insist", "invariant")。

**涉及 dynamic linker 的功能:**

这个头文件本身**并不直接涉及 dynamic linker 的功能**。它的作用是在代码编译和运行时进行断言检查。

然而，断言机制的使用会影响到链接过程，因为包含断言的代码会被编译成目标文件，然后链接器会将这些目标文件链接成可执行文件或共享库 (`.so`)。

**so 布局样本:**

假设一个名为 `libmylib.so` 的共享库使用了 `assertions.h` 中定义的断言：

```
libmylib.so:
    .text:  # 代码段
        my_function:
            ; ... 一些指令 ...
            # 如果启用了断言，这里会包含断言检查的代码
            # 例如，REQUIRE(condition) 可能会被展开成类似
            # 的代码，调用 __assertion_failed 函数
            ; ... 更多指令 ...
    .rodata: # 只读数据段
        # 字符串常量，可能包含断言条件字符串等
    .data:   # 可读写数据段
        # 全局变量，例如 __assertion_failed 指针
    .dynamic: # 动态链接信息
        # ... 包含链接器需要的各种信息 ...
    .symtab:  # 符号表
        # ... 包含函数和变量的符号信息 ...
    .strtab:  # 字符串表
        # ... 包含符号名称等字符串 ...
```

**链接的处理过程:**

1. **编译:**  当包含断言的代码被编译时，如果断言被启用，编译器会将断言宏展开成相应的代码，其中包括可能调用 `__assertion_failed` 函数的代码。
2. **链接:**  链接器会将 `libmylib.so` 和其他依赖的共享库 (包括 Bionic 库，其中定义了 `__assertion_failed`) 链接在一起。链接器会解析符号引用，确保 `libmylib.so` 中对 `__assertion_failed` 的调用能够找到 Bionic 库中对应的实现。
3. **运行时:**  当 `libmylib.so` 被加载到进程的地址空间时，dynamic linker 会负责加载所有依赖的共享库，并进行符号的重定位，确保函数调用能够正确跳转到目标地址。

**逻辑推理、假设输入与输出:**

假设 `CHECK_REQUIRE` 宏被定义为 1 (启用 `REQUIRE` 断言)，并且有以下代码：

```c
#include <isc/assertions.h>
#include <stdio.h>

int divide(int a, int b) {
    REQUIRE(b != 0); // 断言：除数不能为 0
    return a / b;
}

int main() {
    int result = divide(10, 2);
    printf("Result: %d\n", result);

    result = divide(5, 0); // 这里会触发断言失败
    printf("Result: %d\n", result);

    return 0;
}
```

**假设输入:**  程序执行到 `divide(5, 0)`。

**输出:**  由于 `b` 的值为 0，`REQUIRE(b != 0)` 断言失败。`__assertion_failed` 函数会被调用，输出类似以下的错误信息到 stderr：

```
bionic/your_source_file.c:8: assertion failed: b != 0
```

具体的输出格式取决于 `__assertion_failed` 的实现。程序可能会继续执行 (如果断言失败处理没有终止程序)，但后续的行为是未定义的，因为违反了函数的前提条件。

**用户或编程常见的使用错误:**

1. **在发布版本中启用断言:**  断言在运行时会带来性能开销。如果在发布版本中仍然启用大量断言，可能会降低程序的性能。应该使用条件编译来仅在开发和调试版本中启用断言。
2. **在断言中使用有副作用的表达式:**  例如，`REQUIRE(x++)` 是一个错误的做法。因为在发布版本中，断言会被禁用，`x++` 不会被执行，导致开发和发布版本的行为不一致。断言的条件表达式应该只进行检查，而不修改程序状态。
3. **过度依赖断言来处理所有错误:**  断言主要用于检查编程假设是否成立，而不是用于处理所有可能的运行时错误。对于用户输入错误、网络错误等外部因素导致的错误，应该使用更健壮的错误处理机制 (例如，返回值检查、异常处理)。
4. **断言条件过于复杂:**  复杂的断言条件难以理解和维护。应该保持断言的简洁明了，专注于验证核心的假设。
5. **忘记定义断言失败回调函数:**  如果没有定义或链接到 `__assertion_failed` 函数的实现，当断言失败时可能会导致链接错误或未定义的行为。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **NDK 开发 (以 NDK 为例):**
   - 开发者使用 NDK 编写 C/C++ 代码，并在代码中包含 `<isc/assertions.h>` 头文件。
   - 在代码中使用 `REQUIRE`, `ENSURE` 等断言宏来检查代码中的假设。
   - 使用 Android NDK 的构建系统 (通常是 CMake 或 ndk-build) 编译原生代码。
   - 编译器会根据预处理宏的定义 (例如，是否定义了 `_DIAGNOSTIC`) 来决定是否启用断言。如果启用，断言宏会被展开成相应的代码。
   - 链接器会将编译后的目标文件与 Bionic 库 (其中包含 `__assertion_failed` 的实现) 链接在一起。

2. **Android Framework 开发:**
   - Android Framework 的开发者在编写 C/C++ 代码时，也会包含 `<isc/assertions.h>`。
   - Framework 的构建系统 (通常是 Soong) 会编译这些代码。
   - Framework 的构建配置通常会控制断言的启用状态。
   - 链接器会将 Framework 的组件链接到 Bionic 库。

3. **运行时:**
   - 当 Android 系统或应用运行时，如果代码执行到包含断言的地方，并且断言被启用，那么断言条件会被求值。
   - 如果断言条件为假，`__assertion_failed` 函数会被调用。
   - `__assertion_failed` 函数的实现会将断言失败的信息输出到 logcat (Android 的日志系统) 或标准错误流。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `__assertion_failed` 函数来观察断言失败时的信息。以下是一个简单的 Frida hook 示例：

```javascript
// Frida JavaScript 代码

if (Process.platform === 'android') {
  const assertion_failed = Module.findExportByName("libc.so", "__assertion_failed");

  if (assertion_failed) {
    Interceptor.attach(assertion_failed, {
      onEnter: function (args) {
        const file = Memory.readUtf8String(args[0]);
        const line = args[1].toInt();
        const type = args[2].toInt();
        const condition = Memory.readUtf8String(args[3]);
        const err = args[4].toInt();

        console.log(`Assertion Failed:`);
        console.log(`  File: ${file}`);
        console.log(`  Line: ${line}`);
        console.log(`  Type: ${type}`); // 可以根据枚举值转换为字符串
        console.log(`  Condition: ${condition}`);
        console.log(`  Error Flag: ${err}`);
      }
    });

    console.log("Successfully hooked __assertion_failed in libc.so");
  } else {
    console.log("Could not find __assertion_failed in libc.so");
  }
} else {
  console.log("This script is designed for Android.");
}
```

**调试步骤:**

1. **准备 Android 设备或模拟器:** 确保设备已 root 或模拟器配置允许 Frida 连接。
2. **安装 Frida 和 frida-tools:** 在 PC 上安装 Frida 和 frida-tools (`pip install frida-tools`).
3. **找到目标进程:** 确定要调试的 Android 进程的进程 ID 或进程名称。
4. **运行 Frida hook 脚本:** 使用 `frida` 命令将上述 JavaScript 代码注入到目标进程：
   ```bash
   frida -U -f <package_name> -l your_frida_script.js --no-pause
   # 或者
   frida -U <process_name_or_pid> -l your_frida_script.js
   ```
   * `-U`: 连接到 USB 设备。
   * `-f <package_name>`:  启动并附加到指定的应用包名。
   * `-l your_frida_script.js`:  指定 Frida 脚本文件。
   * `--no-pause`:  不暂停进程启动。
5. **触发断言失败:**  在目标应用或系统中执行操作，触发一个预期的断言失败。
6. **观察 Frida 输出:**  当断言失败发生时，Frida 会拦截 `__assertion_failed` 函数的调用，并打印出断言失败的文件名、行号、断言类型、条件以及错误标志等信息。

这个 Frida 脚本可以帮助开发者在运行时动态地观察断言的触发情况，即使这些断言在编译时被禁用了 (如果 `__assertion_failed` 的实现仍然存在)。 然而，需要注意的是，如果 Bionic 库的构建配置完全移除了断言相关的代码，那么可能无法找到 `__assertion_failed` 函数。

Prompt: 
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/include/isc/assertions.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: assertions.h,v 1.5 2009/04/12 17:07:16 christos Exp $	*/

/*
 * Copyright (C) 2004, 2005, 2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1997-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Id: assertions.h,v 1.5 2008/11/14 02:36:51 marka Exp
 */

#ifndef ASSERTIONS_H
#define ASSERTIONS_H		1

typedef enum {
	assert_require, assert_ensure, assert_insist, assert_invariant
} assertion_type;

typedef void (*assertion_failure_callback)(const char *, int, assertion_type,
					   const char *, int);

/* coverity[+kill] */
extern assertion_failure_callback __assertion_failed;
void set_assertion_failure_callback(assertion_failure_callback f);
const char *assertion_type_to_text(assertion_type type);

#if defined(CHECK_ALL) || defined(__COVERITY__)
#define CHECK_REQUIRE		1
#define CHECK_ENSURE		1
#define CHECK_INSIST		1
#define CHECK_INVARIANT		1
#endif

#if defined(CHECK_NONE) && !defined(__COVERITY__)
#define CHECK_REQUIRE		0
#define CHECK_ENSURE		0
#define CHECK_INSIST		0
#define CHECK_INVARIANT		0
#endif

#ifdef _DIAGNOSTIC
#ifndef CHECK_REQUIRE
#define CHECK_REQUIRE		1
#endif

#ifndef CHECK_ENSURE
#define CHECK_ENSURE		1
#endif

#ifndef CHECK_INSIST
#define CHECK_INSIST		1
#endif

#ifndef CHECK_INVARIANT
#define CHECK_INVARIANT		1
#endif
#endif	/* _DIAGNOSTIC */

#if CHECK_REQUIRE != 0
#define REQUIRE(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_require, \
				       #cond, 0), 0)))
#define REQUIRE_ERR(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_require, \
				       #cond, 1), 0)))
#else
#define REQUIRE(cond)		((void) (cond))
#define REQUIRE_ERR(cond)	((void) (cond))
#endif /* CHECK_REQUIRE */

#if CHECK_ENSURE != 0
#define ENSURE(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_ensure, \
				       #cond, 0), 0)))
#define ENSURE_ERR(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_ensure, \
				       #cond, 1), 0)))
#else
#define ENSURE(cond)		((void) (cond))
#define ENSURE_ERR(cond)	((void) (cond))
#endif /* CHECK_ENSURE */

#if CHECK_INSIST != 0
#define INSIST(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_insist, \
				       #cond, 0), 0)))
#define INSIST_ERR(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_insist, \
				       #cond, 1), 0)))
#else
#if !defined(__lint__)
#define INSIST(cond)		((void) (cond))
#define INSIST_ERR(cond)	((void) (cond))
#else /* !__lint__ */
#define INSIST(cond)
#define INSIST_ERR(cond)
#endif /* !__lint__ */
#endif /* CHECK_INSIST */

#if CHECK_INVARIANT != 0
#define INVARIANT(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_invariant, \
				       #cond, 0), 0)))
#define INVARIANT_ERR(cond) \
	((void) ((cond) || \
		 ((__assertion_failed)(__FILE__, __LINE__, assert_invariant, \
				       #cond, 1), 0)))
#else
#define INVARIANT(cond)		((void) (cond))
#define INVARIANT_ERR(cond)	((void) (cond))
#endif /* CHECK_INVARIANT */
#endif /* ASSERTIONS_H */
/*! \file */

"""

```