Response:
Let's break down the thought process for analyzing the `spawn_test.cpp` file and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand what `spawn_test.cpp` does, how it relates to Android, explain the underlying libc functions, delve into dynamic linking (if applicable), discuss potential errors, and trace its usage in the Android framework/NDK. Essentially, it's a reverse engineering and educational exercise.

**2. Initial Scan and Identification of Key Areas:**

First, I'd quickly scan the code to identify the major components:

* **Includes:**  `<spawn.h>`, `<errno.h>`, `<fcntl.h>`, `<sys/cdefs.h>`, `<gtest/gtest.h>`, "SignalUtils.h", "utils.h", `<android-base/file.h>`, `<android-base/strings.h>`. This tells me the file is testing `spawn.h` related functionality, uses Google Test for assertions, and relies on Android-specific utilities.
* **Test Cases:** The `TEST(spawn, ...)` macros immediately highlight the individual tests. I'd quickly list them down as the core functionalities being tested:
    * `posix_spawnattr_init_posix_spawnattr_destroy`
    * `posix_spawnattr_setflags_EINVAL`
    * `posix_spawnattr_setflags_posix_spawnattr_getflags`
    * `posix_spawnattr_setpgroup_posix_spawnattr_getpgroup`
    * `posix_spawnattr_setsigmask_posix_spawnattr_getsigmask`
    * `posix_spawnattr_setsigmask64_posix_spawnattr_getsigmask64`
    * `posix_spawnattr_setsigdefault_posix_spawnattr_getsigdefault`
    * `posix_spawnattr_setsigdefault64_posix_spawnattr_getsigdefault64`
    * `posix_spawnattr_setsschedparam_posix_spawnattr_getsschedparam`
    * `posix_spawnattr_setschedpolicy_posix_spawnattr_getschedpolicy`
    * `posix_spawn`
    * `posix_spawn_not_found`
    * `posix_spawnp`
    * `posix_spawnp_not_found`
    * `posix_spawn_environment`
    * `posix_spawn_file_actions`
    * `posix_spawn_POSIX_SPAWN_SETSID_clear`
    * `posix_spawn_POSIX_SPAWN_SETSID_set`
    * `posix_spawn_POSIX_SPAWN_SETPGROUP_clear`
    * `posix_spawn_POSIX_SPAWN_SETPGROUP_set`
    * `posix_spawn_POSIX_SPAWN_SETSIGMASK`
    * `posix_spawn_POSIX_SPAWN_SETSIGDEF`
    * `signal_stress`
    * `posix_spawn_dup2_CLOEXEC`

**3. Analyzing Individual Test Cases and Connecting to Functionality:**

I would then go through each test case and understand what it's doing and what function(s) it's testing. This is where the detailed explanation of libc functions comes in.

* **`posix_spawnattr_*` tests:** These are clearly testing the attribute manipulation functions related to `posix_spawn`. I'd research each attribute function (`init`, `destroy`, `setflags`, `getflags`, `setpgroup`, `getpgroup`, etc.) and explain their purpose in controlling how the child process is spawned.
* **`posix_spawn` and `posix_spawnp` tests:** These are testing the core spawning functions. I'd highlight the difference between them (path lookup) and their basic usage. The "not_found" tests are important for demonstrating error handling.
* **`posix_spawn_environment`:** This tests the ability to pass environment variables to the spawned process.
* **`posix_spawn_file_actions`:** This is a more complex test dealing with manipulating file descriptors during the spawn process. I'd focus on `posix_spawn_file_actions_init`, `addclose`, `adddup2`, `addopen`, `addfchdir_np`, `addchdir_np`, and `destroy`.
* **`posix_spawn_POSIX_SPAWN_*` tests:** These focus on testing specific flags for `posix_spawnattr_setflags`, like `POSIX_SPAWN_SETSID`, `POSIX_SPAWN_SETPGROUP`, `POSIX_SPAWN_SETSIGMASK`, and `POSIX_SPAWN_SETSIGDEF`. I'd explain the effect of each flag.
* **`signal_stress`:**  This test is about signal handling during `posix_spawn`, specifically ensuring signals are correctly defaulted in the child.
* **`posix_spawn_dup2_CLOEXEC`:** This tests the interaction between `dup2` and the `O_CLOEXEC` flag in the context of `posix_spawn`.

**4. Addressing Android-Specific Aspects:**

As I analyze the test cases, I'd look for connections to Android:

* **Bionic:** The file is in `bionic/tests`, so it's directly testing Bionic's implementation.
* **Android Headers:** The inclusion of `<android-base/file.h>` and `<android-base/strings.h>` shows the test uses Android-specific utility functions.
* **Reserved Signals:** The `#elif defined(__BIONIC__)` block indicates special handling for Bionic-specific reserved signals. This is a crucial Android connection.
* **NDK/Framework Relevance:** I would think about how `posix_spawn` is used in Android. Starting new processes is fundamental. This leads to examples in `Runtime.exec()`, `ProcessBuilder`, and potentially native daemons started by the framework.

**5. Dynamic Linking Considerations:**

While `posix_spawn` itself doesn't *directly* involve the dynamic linker in the sense of resolving symbols during the `posix_spawn` call itself, the *child process* that is spawned will go through dynamic linking. Therefore, I would explain:

* **SO Layout:** A basic example of a linked executable and its dependencies.
* **Linking Process:** Briefly describe how the dynamic linker (`linker64` or `linker`) resolves symbols in the child process. The `LD_LIBRARY_PATH` environment variable is relevant here.

**6. Potential Errors and Common Mistakes:**

Based on my understanding of `posix_spawn` and related functions, I'd brainstorm common errors:

* **Incorrect arguments:**  `nullptr` where it shouldn't be, wrong number of arguments.
* **File not found:** For `posix_spawn` when the full path is incorrect.
* **Permissions issues:** Trying to execute a non-executable file.
* **Incorrect file actions:**  Leaking file descriptors or not setting them up correctly.
* **Signal handling issues:** Incorrectly setting signal masks or defaults.

**7. Frida Hooking:**

To demonstrate debugging, I'd provide Frida snippets for hooking key functions like `posix_spawn`, `posix_spawnp`, and potentially the attribute setting functions. The goal is to show how to intercept these calls and inspect their arguments and return values.

**8. Structuring the Response:**

Finally, I'd organize the information logically, following the prompt's structure:

* **Functionality Summary:** A concise overview.
* **Relationship to Android:** Specific examples and connections.
* **Libc Function Details:**  In-depth explanation of each function used.
* **Dynamic Linker Details:** SO layout and linking process.
* **Assumptions and Input/Output (where applicable):** Examples for clarity.
* **Common Usage Errors:** Practical examples of mistakes.
* **Android Framework/NDK Path:** Explaining how the call chain might look.
* **Frida Hook Examples:** Concrete code snippets.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe dynamic linking isn't that relevant. **Correction:**  While not directly part of the `posix_spawn` *call*, it's crucial for the *child process*, so I should include a basic explanation.
* **Initial thought:** Just list the libc functions. **Correction:**  The prompt asks for *how* they are implemented. I need to explain their purpose and effect.
* **Initial thought:**  Focus only on successful scenarios. **Correction:**  The prompt specifically asks for common errors, which is important for practical understanding.

By following this structured thought process, breaking down the code into manageable parts, and connecting the specific details to the broader Android context, I can generate a comprehensive and informative response.
## 对 bionic/tests/spawn_test.cpp 的功能、Android 关系、libc 函数、动态链接、错误、以及 Frida Hook 的详细解释

这个 `bionic/tests/spawn_test.cpp` 文件是 Android Bionic 库中的一个测试文件，专门用来测试与进程创建相关的函数，主要是 `spawn.h` 中定义的 `posix_spawn` 和 `posix_spawnp` 及其相关的属性操作函数。

**1. 文件功能列表:**

该文件主要测试以下功能：

* **`posix_spawnattr_init` 和 `posix_spawnattr_destroy`:** 测试初始化和销毁 `posix_spawn` 属性对象的功能。
* **`posix_spawnattr_setflags` 和 `posix_spawnattr_getflags`:** 测试设置和获取 `posix_spawn` 属性中的标志位，例如 `POSIX_SPAWN_RESETIDS`、`POSIX_SPAWN_SETPGROUP`、`POSIX_SPAWN_SETSIGDEF`、`POSIX_SPAWN_SETSIGMASK`、`POSIX_SPAWN_SETSCHEDPARAM`、`POSIX_SPAWN_SETSCHEDULER`、`POSIX_SPAWN_USEVFORK`、`POSIX_SPAWN_SETSID`。
* **`posix_spawnattr_setpgroup` 和 `posix_spawnattr_getpgroup`:** 测试设置和获取子进程的进程组 ID。
* **`posix_spawnattr_setsigmask` 和 `posix_spawnattr_getsigmask`:** 测试设置和获取子进程的信号掩码（哪些信号会被阻塞）。
* **`posix_spawnattr_setsigmask64` 和 `posix_spawnattr_getsigmask64`:**  与上一个功能类似，但使用 `sigset64_t` 处理超过标准信号范围的信号。
* **`posix_spawnattr_setsigdefault` 和 `posix_spawnattr_getsigdefault`:** 测试设置和获取子进程的信号处理方式（设置为默认）。
* **`posix_spawnattr_setsigdefault64` 和 `posix_spawnattr_getsigdefault64`:** 与上一个功能类似，但使用 `sigset64_t`。
* **`posix_spawnattr_setschedparam` 和 `posix_spawnattr_getsschedparam`:** 测试设置和获取子进程的调度参数（例如优先级）。
* **`posix_spawnattr_setschedpolicy` 和 `posix_spawnattr_getschedpolicy`:** 测试设置和获取子进程的调度策略（例如 `SCHED_FIFO`）。
* **`posix_spawn`:** 测试在指定路径下执行新程序的功能。
* **`posix_spawn_not_found`:** 测试当 `posix_spawn` 指定的程序路径不存在时的行为。
* **`posix_spawnp`:** 测试在 `PATH` 环境变量中查找并执行新程序的功能。
* **`posix_spawnp_not_found`:** 测试当 `posix_spawnp` 指定的程序在 `PATH` 中找不到时的行为。
* **`posix_spawn_environment`:** 测试向新创建的进程传递环境变量的功能。
* **`posix_spawn_file_actions`:** 测试在创建新进程时执行文件操作，例如关闭、复制文件描述符、打开文件、改变工作目录等。
* **`posix_spawn` 与 `POSIX_SPAWN_SETSID`、`POSIX_SPAWN_SETPGROUP`、`POSIX_SPAWN_SETSIGMASK`、`POSIX_SPAWN_SETSIGDEF` 标志的组合测试:** 测试这些标志对子进程会话 ID、进程组 ID、信号掩码和信号处理方式的影响。
* **`signal_stress`:** 进行信号压力测试，确保 `posix_spawn` 能正确处理信号。
* **`posix_spawn_dup2_CLOEXEC`:** 测试 `posix_spawn_file_actions_adddup2` 如何处理带有 `O_CLOEXEC` 标志的文件描述符。

**2. 与 Android 功能的关系及举例说明:**

`posix_spawn` 和 `posix_spawnp` 是在 Android 系统中创建新进程的关键底层函数。它们比 `fork` 后跟 `execve` 更有效率，因为它们将进程创建和程序加载合二为一，减少了不必要的资源复制。

**举例说明:**

* **Android Framework 中的 `Runtime.exec()` 和 `ProcessBuilder`:** 这些 Java API 最终会调用 native 代码，而 native 代码很可能会使用 `posix_spawn` 或 `posix_spawnp` 来启动新的进程，例如执行 shell 命令或启动其他应用。
* **NDK 开发中的进程创建:** 使用 NDK 进行 native 开发时，开发者可以使用 `posix_spawn` 或 `posix_spawnp` 来创建子进程，例如实现多进程应用。
* **`adb shell` 命令的执行:** 当你在 PC 上使用 `adb shell` 命令连接到 Android 设备并执行命令时，`adb` 服务会在 Android 设备上创建一个新的进程来执行该命令，这很可能就是通过 `posix_spawn` 或 `posix_spawnp` 实现的。
* **系统服务 (system services) 的启动:** Android 系统启动时，init 进程会启动各种系统服务，这些服务的启动很可能也使用了 `posix_spawn` 或 `posix_spawnp`。

**3. libc 函数的功能实现详解:**

以下是代码中涉及的一些关键 libc 函数的功能实现详解：

* **`posix_spawn` 和 `posix_spawnp`:**
    * **功能:**  用于创建一个新的进程并执行指定的程序。`posix_spawn` 需要提供可执行文件的完整路径，而 `posix_spawnp` 会在 `PATH` 环境变量指定的目录中搜索可执行文件。
    * **实现 (简化描述):**
        1. **创建子进程:** 底层通常会使用 `clone` 系统调用创建一个新的进程。这个新的进程会复制父进程的大部分资源，例如内存映射、打开的文件描述符等。
        2. **应用属性:** 如果提供了 `posix_spawnattr_t` 对象，系统会根据其中设置的标志和参数来配置子进程，例如设置进程组 ID、信号掩码、调度策略等。
        3. **执行文件操作:** 如果提供了 `posix_spawn_file_actions_t` 对象，系统会执行其中定义的文件操作，例如关闭、复制文件描述符等。
        4. **加载和执行新程序:** 使用 `execve` 系统调用将子进程的内存空间替换为要执行的程序，并开始执行新程序的代码。`posix_spawn` 直接使用提供的路径，`posix_spawnp` 会先查找路径。
* **`posix_spawnattr_init(posix_spawnattr_t *attr)`:**
    * **功能:** 初始化 `posix_spawn` 属性对象。
    * **实现:**  通常会将 `posix_spawnattr_t` 结构体的成员设置为默认值，例如标志位清零，信号掩码设置为空，调度参数设置为默认值等。
* **`posix_spawnattr_destroy(posix_spawnattr_t *attr)`:**
    * **功能:** 销毁 `posix_spawn` 属性对象，释放其占用的资源。
    * **实现:**  如果属性对象中分配了动态内存，则会释放这些内存。对于简单的结构体，可能只是一个空操作或者将成员重置。
* **`posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags)`:**
    * **功能:** 设置 `posix_spawn` 属性对象中的标志位。这些标志位控制子进程创建时的行为。
    * **实现:**  会将传入的 `flags` 值赋值给 `posix_spawnattr_t` 结构体中用于存储标志位的成员。会进行一些基本的校验，例如代码中测试的 `EINVAL` 错误，即当设置了不支持的标志位时返回错误。
* **`posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags)`:**
    * **功能:** 获取 `posix_spawn` 属性对象中的标志位。
    * **实现:**  将 `posix_spawnattr_t` 结构体中存储的标志位的值复制到 `flags` 指向的内存。
* **`posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup)`:**
    * **功能:** 设置子进程的进程组 ID。
    * **实现:** 将传入的 `pgroup` 值存储到 `posix_spawnattr_t` 结构体中相应的成员。
* **`posix_spawnattr_getpgroup(const posix_spawnattr_t *attr, pid_t *pgroup)`:**
    * **功能:** 获取子进程的进程组 ID。
    * **实现:** 将 `posix_spawnattr_t` 结构体中存储的进程组 ID 复制到 `pgroup` 指向的内存。
* **`posix_spawnattr_setsigmask(posix_spawnattr_t *attr, const sigset_t *sigmask)` 和 `posix_spawnattr_getsigmask`:**
    * **功能:** 设置和获取子进程的信号掩码。
    * **实现:** 内部会复制 `sigmask` 中的信号到 `posix_spawnattr_t` 结构体中用于存储信号掩码的成员。`getsigmask` 则做相反的操作。
* **`posix_spawnattr_setsigdefault(posix_spawnattr_t *attr, const sigset_t *sigdefault)` 和 `posix_spawnattr_getsigdefault`:**
    * **功能:** 设置和获取子进程的信号处理方式为默认。
    * **实现:** 类似于信号掩码的处理，将需要设置为默认处理方式的信号存储在 `posix_spawnattr_t` 中。
* **`posix_spawnattr_setschedparam(posix_spawnattr_t *attr, const struct sched_param *param)` 和 `posix_spawnattr_getsschedparam`:**
    * **功能:** 设置和获取子进程的调度参数，例如优先级。
    * **实现:** 复制 `sched_param` 结构体的内容到 `posix_spawnattr_t` 中。
* **`posix_spawnattr_setschedpolicy(posix_spawnattr_t *attr, int policy)` 和 `posix_spawnattr_getschedpolicy`:**
    * **功能:** 设置和获取子进程的调度策略。
    * **实现:** 存储调度策略的值到 `posix_spawnattr_t` 中。
* **`posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions)` 和 `posix_spawn_file_actions_destroy`:**
    * **功能:** 初始化和销毁用于存储文件操作的结构体。
    * **实现:**  初始化可能会分配内存来存储文件操作列表。销毁会释放这些内存。
* **`posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions, int fd)`:**
    * **功能:**  指定在子进程中关闭指定的文件描述符。
    * **实现:**  将要关闭的文件描述符 `fd` 添加到 `file_actions` 结构体维护的文件操作列表中。
* **`posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions, int oldfd, int newfd)`:**
    * **功能:** 指定在子进程中将 `oldfd` 复制到 `newfd` (相当于 `dup2(oldfd, newfd)`)。
    * **实现:**  将 `oldfd` 和 `newfd` 的信息添加到文件操作列表中。
* **`posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *file_actions, int fd, const char *path, int oflag, mode_t mode)`:**
    * **功能:** 指定在子进程中打开指定的文件，并将其文件描述符设置为 `fd`。
    * **实现:**  将文件路径、打开标志、模式以及目标文件描述符添加到文件操作列表中。
* **`posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t *file_actions, int fd)`:**
    * **功能:** (非 POSIX 标准，Bionic 扩展) 指定在子进程中将工作目录更改为文件描述符 `fd` 指向的目录。
    * **实现:**  将文件描述符添加到文件操作列表中，并在子进程创建时执行 `fchdir(fd)`。
* **`posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *file_actions, const char *path)`:**
    * **功能:** (非 POSIX 标准，Bionic 扩展) 指定在子进程中将工作目录更改为 `path`。
    * **实现:**  将路径添加到文件操作列表中，并在子进程创建时执行 `chdir(path)`。

**4. 涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

`posix_spawn` 和 `posix_spawnp` 本身并不直接涉及到动态链接器的功能。动态链接发生在子进程被创建并准备执行新程序时。

**so 布局样本 (子进程执行的程序):**

假设子进程要执行的程序是一个名为 `my_app` 的可执行文件，它链接了 `libc.so` 和一个自定义的动态库 `libcustom.so`。

```
my_app (可执行文件)
├── .interp (指向动态链接器的路径，例如 /system/bin/linker64 或 /system/bin/linker)
├── .dynamic (包含动态链接信息的段)
│   ├── DT_NEEDED: libc.so
│   ├── DT_NEEDED: libcustom.so
│   └── ...
├── 其他代码和数据段
libc.so (动态库)
libcustom.so (自定义动态库)
```

**链接的处理过程 (在子进程中):**

1. **动态链接器启动:** 当子进程被创建并执行 `my_app` 时，内核会根据 `.interp` 段的信息启动动态链接器 (例如 `/system/bin/linker64`)。
2. **加载依赖库:** 动态链接器会解析 `my_app` 的 `.dynamic` 段，找到 `DT_NEEDED` 条目，确定 `my_app` 依赖的动态库 (`libc.so` 和 `libcustom.so`)。
3. **查找依赖库:** 动态链接器会在预定义的路径（例如 `/system/lib64`, `/vendor/lib64`，以及 `LD_LIBRARY_PATH` 环境变量指定的路径）中查找这些依赖库。
4. **加载依赖库:** 找到依赖库后，动态链接器会将它们加载到子进程的内存空间中。
5. **符号解析 (Symbol Resolution):** 动态链接器会解析 `my_app` 和其依赖库中的符号表，将 `my_app` 中引用的外部符号（例如 `printf` 来自 `libc.so` 中的函数）与它们在依赖库中的实际地址关联起来。这个过程称为重定位 (Relocation)。
6. **执行程序:** 完成符号解析后，动态链接器会将控制权交给 `my_app` 的入口点，程序开始执行。

**注意:** `posix_spawn` 的 `file_actions` 参数可以影响子进程加载动态库的环境，例如通过改变工作目录或打开特定的文件。

**5. 假设输入与输出 (逻辑推理):**

以 `TEST(spawn, posix_spawn_environment)` 为例：

**假设输入:**

* 父进程执行该测试。
* `ExecTestHelper` 设置要执行的程序为 `sh`，参数为 `"-c"` 和 `"exit $posix_spawn_environment_test"`。
* `ExecTestHelper` 设置环境变量 `posix_spawn_environment_test=66`。

**逻辑推理:**

* `posix_spawnp` 被调用，创建子进程并执行 `/system/bin/sh` (假设 `sh` 在 PATH 中)。
* 子进程执行 `sh -c "exit $posix_spawn_environment_test"`。
* shell 会展开环境变量 `$posix_spawn_environment_test`，其值为 `66`。
* `exit 66` 命令会使 shell 进程以状态码 66 退出。

**输出:**

* `AssertChildExited(pid, 66)` 断言成功，因为子进程的退出状态码为 66。

**6. 用户或编程常见的使用错误举例说明:**

* **错误地使用 `posix_spawn` 的路径:**
    ```c++
    pid_t pid;
    // 假设 "my_program" 不在当前目录或 PATH 中
    int ret = posix_spawn(&pid, "my_program", nullptr, nullptr, nullptr, nullptr);
    if (ret != 0) {
        perror("posix_spawn failed"); // 可能会输出 "posix_spawn failed: No such file or directory"
    }
    ```
    **正确做法:**  如果使用 `posix_spawn`，需要提供可执行文件的完整路径，或者使用 `posix_spawnp` 让系统在 PATH 中查找。

* **忘记初始化或销毁 `posix_spawnattr_t` 或 `posix_spawn_file_actions_t`:**
    ```c++
    posix_spawnattr_t attr;
    // 忘记 posix_spawnattr_init(&attr);
    pid_t pid;
    posix_spawn(&pid, "/bin/ls", nullptr, &attr, nullptr, nullptr); // 可能导致未定义的行为
    // 忘记 posix_spawnattr_destroy(&attr);
    ```
    **正确做法:**  始终要配对使用 `_init` 和 `_destroy` 函数。

* **文件描述符泄露:**  在使用 `posix_spawn_file_actions` 时，如果没有正确地关闭不再需要的文件描述符，可能会导致文件描述符泄露。
    ```c++
    int pipefd[2];
    pipe(pipefd);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
    // 忘记关闭 pipefd[0] 和 pipefd[1] 在父进程中的拷贝
    pid_t pid;
    posix_spawnp(&pid, "ls", &fa, nullptr, nullptr, nullptr);
    posix_spawn_file_actions_destroy(&fa);
    // ...
    ```
    **正确做法:**  在父进程中关闭不再需要的管道或文件描述符。

* **信号处理不当:**  没有正确设置子进程的信号掩码或默认处理方式，导致子进程行为异常。

**7. 说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `posix_spawn` 的路径示例 (以 `Runtime.exec()` 为例):**

1. **Java 代码:** 在 Java 代码中调用 `Runtime.getRuntime().exec(command)` 或 `ProcessBuilder`.
2. **`java.lang.ProcessImpl`:**  这些 Java API 最终会调用到 `java.lang.ProcessImpl` 的 native 方法 `forkAndExec`.
3. **Native 代码 (`ProcessImpl.c` 或相关 JNI 代码):** `forkAndExec` native 方法会执行以下操作：
    * 进行必要的参数转换和准备。
    * 调用 `fork()` 系统调用创建子进程。
    * 在子进程中，可能会设置进程组、信号处理等。
    * **关键点:**  最终会调用 `execve()` 或更底层的进程创建函数，在较新的 Android 版本中，为了效率和灵活性，很可能会使用 `posix_spawn` 或 `posix_spawnp` 来替代 `fork` + `execve` 的组合。
4. **Bionic libc (`bionic/libc/bionic/`):**  `posix_spawn` 和 `posix_spawnp` 的实现位于 Bionic libc 中。

**NDK 到 `posix_spawn` 的路径示例:**

1. **NDK C/C++ 代码:** 开发者在 NDK 代码中直接包含 `<spawn.h>` 并调用 `posix_spawn` 或 `posix_spawnp`.
2. **Bionic libc:**  NDK 编译的 native 代码链接到 Android 设备的 Bionic libc，因此直接调用 Bionic 提供的 `posix_spawn` 和 `posix_spawnp` 实现。

**Frida Hook 示例:**

以下是一些使用 Frida hook `posix_spawn` 和相关函数的示例：

```javascript
// Hook posix_spawn
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawn"), {
  onEnter: function (args) {
    console.log("posix_spawn called");
    console.log("  pid*: " + args[0]);
    console.log("  path: " + Memory.readUtf8String(args[1]));
    // 打印 argv
    var argv = new NativePointer(args[4]);
    if (!argv.isNull()) {
      console.log("  argv:");
      for (let i = 0; ; i++) {
        var arg = argv.readPointer();
        if (arg.isNull()) break;
        console.log("    " + Memory.readUtf8String(arg));
        argv = argv.add(Process.pointerSize);
      }
    }
    // 可以进一步解析 posix_spawnattr_t 和 posix_spawn_file_actions_t
  },
  onLeave: function (retval) {
    console.log("posix_spawn returned: " + retval);
  }
});

// Hook posix_spawnp
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawnp"), {
  onEnter: function (args) {
    console.log("posix_spawnp called");
    console.log("  pid*: " + args[0]);
    console.log("  file: " + Memory.readUtf8String(args[1]));
    // ... (类似 posix_spawn 的参数打印)
  },
  onLeave: function (retval) {
    console.log("posix_spawnp returned: " + retval);
  }
});

// Hook posix_spawnattr_setflags
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawnattr_setflags"), {
  onEnter: function (args) {
    console.log("posix_spawnattr_setflags called");
    console.log("  attr*: " + args[0]);
    console.log("  flags: " + args[1]);
  }
});

// Hook posix_spawn_file_actions_adddup2
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawn_file_actions_adddup2"), {
  onEnter: function (args) {
    console.log("posix_spawn_file_actions_adddup2 called");
    console.log("  file_actions*: " + args[0]);
    console.log("  oldfd: " + args[1]);
    console.log("  newfd: " + args[2]);
  }
});
```

这些 Frida 脚本可以帮助你动态地观察 `posix_spawn` 及其相关函数的调用，查看传递的参数，从而理解 Android 系统或应用是如何使用这些底层机制来创建新进程的。你可以根据需要 hook 其他相关的函数，例如 `posix_spawnattr_init`、`posix_spawnattr_setpgroup` 等，以更详细地分析进程创建的每个步骤。

Prompt: 
```
这是目录为bionic/tests/spawn_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <spawn.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/cdefs.h>

#include <gtest/gtest.h>

#include "SignalUtils.h"
#include "utils.h"

#include <android-base/file.h>
#include <android-base/strings.h>

// Old versions of glibc didn't have POSIX_SPAWN_SETSID.
#if __GLIBC__
# if !defined(POSIX_SPAWN_SETSID)
#  define POSIX_SPAWN_SETSID 0
# endif
#elif defined(__BIONIC__)
#include <platform/bionic/reserved_signals.h>
#endif

TEST(spawn, posix_spawnattr_init_posix_spawnattr_destroy) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setflags_EINVAL) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(EINVAL, posix_spawnattr_setflags(&sa, ~0));
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setflags_posix_spawnattr_getflags) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, POSIX_SPAWN_RESETIDS));
  short flags;
  ASSERT_EQ(0, posix_spawnattr_getflags(&sa, &flags));
  ASSERT_EQ(POSIX_SPAWN_RESETIDS, flags);

  constexpr short all_flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
                              POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSCHEDPARAM |
                              POSIX_SPAWN_SETSCHEDULER | POSIX_SPAWN_USEVFORK | POSIX_SPAWN_SETSID;
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, all_flags));
  ASSERT_EQ(0, posix_spawnattr_getflags(&sa, &flags));
  ASSERT_EQ(all_flags, flags);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setpgroup_posix_spawnattr_getpgroup) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  ASSERT_EQ(0, posix_spawnattr_setpgroup(&sa, 123));
  pid_t g;
  ASSERT_EQ(0, posix_spawnattr_getpgroup(&sa, &g));
  ASSERT_EQ(123, g);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setsigmask_posix_spawnattr_getsigmask) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  sigset_t sigs;
  ASSERT_EQ(0, posix_spawnattr_getsigmask(&sa, &sigs));
  ASSERT_FALSE(sigismember(&sigs, SIGALRM));

  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, posix_spawnattr_setsigmask(&sa, &just_SIGALRM));

  ASSERT_EQ(0, posix_spawnattr_getsigmask(&sa, &sigs));
  ASSERT_TRUE(sigismember(&sigs, SIGALRM));

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setsigmask64_posix_spawnattr_getsigmask64) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  sigset64_t sigs;
  ASSERT_EQ(0, posix_spawnattr_getsigmask64(&sa, &sigs));
  ASSERT_FALSE(sigismember64(&sigs, SIGRTMIN));

  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, posix_spawnattr_setsigmask64(&sa, &just_SIGRTMIN));

  ASSERT_EQ(0, posix_spawnattr_getsigmask64(&sa, &sigs));
  ASSERT_TRUE(sigismember64(&sigs, SIGRTMIN));

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setsigdefault_posix_spawnattr_getsigdefault) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  sigset_t sigs;
  ASSERT_EQ(0, posix_spawnattr_getsigdefault(&sa, &sigs));
  ASSERT_FALSE(sigismember(&sigs, SIGALRM));

  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, posix_spawnattr_setsigdefault(&sa, &just_SIGALRM));

  ASSERT_EQ(0, posix_spawnattr_getsigdefault(&sa, &sigs));
  ASSERT_TRUE(sigismember(&sigs, SIGALRM));

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setsigdefault64_posix_spawnattr_getsigdefault64) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  sigset64_t sigs;
  ASSERT_EQ(0, posix_spawnattr_getsigdefault64(&sa, &sigs));
  ASSERT_FALSE(sigismember64(&sigs, SIGRTMIN));

  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, posix_spawnattr_setsigdefault64(&sa, &just_SIGRTMIN));

  ASSERT_EQ(0, posix_spawnattr_getsigdefault64(&sa, &sigs));
  ASSERT_TRUE(sigismember64(&sigs, SIGRTMIN));

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setsschedparam_posix_spawnattr_getsschedparam) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  sched_param sp;
  ASSERT_EQ(0, posix_spawnattr_getschedparam(&sa, &sp));
  ASSERT_EQ(0, sp.sched_priority);

  sched_param sp123 = { .sched_priority = 123 };
  ASSERT_EQ(0, posix_spawnattr_setschedparam(&sa, &sp123));

  ASSERT_EQ(0, posix_spawnattr_getschedparam(&sa, &sp));
  ASSERT_EQ(123, sp.sched_priority);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawnattr_setschedpolicy_posix_spawnattr_getschedpolicy) {
  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  int p;
  ASSERT_EQ(0, posix_spawnattr_getschedpolicy(&sa, &p));
  ASSERT_EQ(0, p);

  ASSERT_EQ(0, posix_spawnattr_setschedpolicy(&sa, SCHED_FIFO));

  ASSERT_EQ(0, posix_spawnattr_getschedpolicy(&sa, &p));
  ASSERT_EQ(SCHED_FIFO, p);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawn) {
  ExecTestHelper eth;
  eth.SetArgs({BIN_DIR "true", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawn(&pid, eth.GetArg0(), nullptr, nullptr, eth.GetArgs(), nullptr));
  AssertChildExited(pid, 0);
}

TEST(spawn, posix_spawn_not_found) {
  ExecTestHelper eth;
  eth.SetArgs({"true", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawn(&pid, eth.GetArg0(), nullptr, nullptr, eth.GetArgs(), nullptr));
  AssertChildExited(pid, 127);
}

TEST(spawn, posix_spawnp) {
  ExecTestHelper eth;
  eth.SetArgs({"true", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), nullptr, nullptr, eth.GetArgs(), nullptr));
  AssertChildExited(pid, 0);
}

TEST(spawn, posix_spawnp_not_found) {
  ExecTestHelper eth;
  eth.SetArgs({"does-not-exist", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), nullptr, nullptr, eth.GetArgs(), nullptr));
  AssertChildExited(pid, 127);
}

TEST(spawn, posix_spawn_environment) {
  ExecTestHelper eth;
  eth.SetArgs({"sh", "-c", "exit $posix_spawn_environment_test", nullptr});
  eth.SetEnv({"posix_spawn_environment_test=66", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), nullptr, nullptr, eth.GetArgs(), eth.GetEnv()));
  AssertChildExited(pid, 66);
}

TEST(spawn, posix_spawn_file_actions) {
#if !defined(__GLIBC__)
  int fds[2];
  ASSERT_NE(-1, pipe(fds));

  posix_spawn_file_actions_t fa;
  ASSERT_EQ(0, posix_spawn_file_actions_init(&fa));

  // Test addclose and adddup2 by redirecting output to the pipe created above.
  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[0]));
  ASSERT_EQ(0, posix_spawn_file_actions_adddup2(&fa, fds[1], 1));
  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[1]));
  // Check that close(2) failures are ignored by closing the same fd again.
  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[1]));
  // Open a file directly, to test addopen.
  ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 56, "/proc/version", O_RDONLY, 0));
  // Test addfchdir by opening the same file a second way...
  ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 57, "/proc", O_PATH, 0));
  ASSERT_EQ(0, posix_spawn_file_actions_addfchdir_np(&fa, 57));
  ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 58, "version", O_RDONLY, 0));
  // Test addchdir by opening the same file a third way...
  ASSERT_EQ(0, posix_spawn_file_actions_addchdir_np(&fa, "/"));
  ASSERT_EQ(0, posix_spawn_file_actions_addopen(&fa, 59, "proc/version", O_RDONLY, 0));

  ExecTestHelper eth;
  eth.SetArgs({"ls", "-l", "/proc/self/fd", nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), &fa, nullptr, eth.GetArgs(), eth.GetEnv()));
  ASSERT_EQ(0, posix_spawn_file_actions_destroy(&fa));

  ASSERT_EQ(0, close(fds[1]));
  std::string content;
  ASSERT_TRUE(android::base::ReadFdToString(fds[0], &content));
  ASSERT_EQ(0, close(fds[0]));

  AssertChildExited(pid, 0);

  // We'll know the dup2 worked if we see any ls(1) output in our pipe.
  // The opens we can check manually (and they implicitly check the chdirs)...
  bool open_to_fd_56_worked = false;
  bool open_to_fd_58_worked = false;
  bool open_to_fd_59_worked = false;
  for (const auto& line : android::base::Split(content, "\n")) {
    if (line.find(" 56 -> /proc/version") != std::string::npos) open_to_fd_56_worked = true;
    if (line.find(" 58 -> /proc/version") != std::string::npos) open_to_fd_58_worked = true;
    if (line.find(" 59 -> /proc/version") != std::string::npos) open_to_fd_59_worked = true;
  }
  ASSERT_TRUE(open_to_fd_56_worked) << content;
  ASSERT_TRUE(open_to_fd_58_worked) << content;
  ASSERT_TRUE(open_to_fd_59_worked) << content;
#else
  GTEST_SKIP() << "our old glibc doesn't have the chdirs; newer versions and musl do.";
#endif
}

static void CatFileToString(posix_spawnattr_t* sa, const char* path, std::string* content) {
  int fds[2];
  ASSERT_NE(-1, pipe(fds));

  posix_spawn_file_actions_t fa;
  ASSERT_EQ(0, posix_spawn_file_actions_init(&fa));
  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[0]));
  ASSERT_EQ(0, posix_spawn_file_actions_adddup2(&fa, fds[1], 1));
  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[1]));

  ExecTestHelper eth;
  eth.SetArgs({"cat", path, nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), &fa, sa, eth.GetArgs(), nullptr));
  ASSERT_EQ(0, posix_spawn_file_actions_destroy(&fa));

  ASSERT_EQ(0, close(fds[1]));
  ASSERT_TRUE(android::base::ReadFdToString(fds[0], content));
  ASSERT_EQ(0, close(fds[0]));
  AssertChildExited(pid, 0);
}

struct ProcStat {
  pid_t pid;
  pid_t ppid;
  pid_t pgrp;
  pid_t sid;
};

static __attribute__((unused)) void GetChildStat(posix_spawnattr_t* sa, ProcStat* ps) {
  std::string content;
  CatFileToString(sa, "/proc/self/stat", &content);

  ASSERT_EQ(4, sscanf(content.c_str(), "%d (cat) %*c %d %d %d", &ps->pid, &ps->ppid, &ps->pgrp,
                      &ps->sid));

  ASSERT_EQ(getpid(), ps->ppid);
}

struct ProcStatus {
  uint64_t sigblk;
  uint64_t sigign;
};

static void __attribute__((unused)) GetChildStatus(posix_spawnattr_t* sa, ProcStatus* ps) {
  std::string content;
  CatFileToString(sa, "/proc/self/status", &content);

  bool saw_blk = false;
  bool saw_ign = false;
  for (const auto& line : android::base::Split(content, "\n")) {
    if (sscanf(line.c_str(), "SigBlk: %" SCNx64, &ps->sigblk) == 1) saw_blk = true;
    if (sscanf(line.c_str(), "SigIgn: %" SCNx64, &ps->sigign) == 1) saw_ign = true;
  }
  ASSERT_TRUE(saw_blk);
  ASSERT_TRUE(saw_ign);
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETSID_clear) {
  pid_t parent_sid = getsid(0);

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, 0));

  ProcStat ps = {};
  GetChildStat(&sa, &ps);
  ASSERT_EQ(parent_sid, ps.sid);
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETSID_set) {
  pid_t parent_sid = getsid(0);

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSID));

  ProcStat ps = {};
  GetChildStat(&sa, &ps);
  ASSERT_NE(parent_sid, ps.sid);
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETPGROUP_clear) {
  pid_t parent_pgrp = getpgrp();

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, 0));

  ProcStat ps = {};
  GetChildStat(&sa, &ps);
  ASSERT_EQ(parent_pgrp, ps.pgrp);
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETPGROUP_set) {
  pid_t parent_pgrp = getpgrp();

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));
  ASSERT_EQ(0, posix_spawnattr_setpgroup(&sa, 0));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETPGROUP));

  ProcStat ps = {};
  GetChildStat(&sa, &ps);
  ASSERT_NE(parent_pgrp, ps.pgrp);
  // Setting pgid 0 means "the same as the caller's pid".
  ASSERT_EQ(ps.pid, ps.pgrp);
  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETSIGMASK) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "glibc doesn't ignore the same signals.";
#else
  // Block SIGBUS in the parent...
  sigset_t just_SIGBUS;
  sigemptyset(&just_SIGBUS);
  sigaddset(&just_SIGBUS, SIGBUS);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGBUS, nullptr));

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  // Ask for only SIGALRM to be blocked in the child...
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, posix_spawnattr_setsigmask(&sa, &just_SIGALRM));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK));

  // Check that's what happens...
  ProcStatus ps = {};
  GetChildStatus(&sa, &ps);

  // TIMER_SIGNAL should also be blocked.
  uint64_t expected_blocked = 0;
  SignalSetAdd(&expected_blocked, SIGALRM);
  SignalSetAdd(&expected_blocked, BIONIC_SIGNAL_POSIX_TIMERS);
  EXPECT_EQ(expected_blocked, ps.sigblk);

  uint64_t expected_ignored = 0;
  SignalSetAdd(&expected_ignored, BIONIC_SIGNAL_ART_PROFILER);
  EXPECT_EQ(expected_ignored, ps.sigign);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
#endif
}

TEST(spawn, posix_spawn_POSIX_SPAWN_SETSIGDEF) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "glibc doesn't ignore the same signals.";
#else
  // Ignore SIGALRM and SIGCONT in the parent...
  ASSERT_NE(SIG_ERR, signal(SIGALRM, SIG_IGN));
  ASSERT_NE(SIG_ERR, signal(SIGCONT, SIG_IGN));

  posix_spawnattr_t sa;
  ASSERT_EQ(0, posix_spawnattr_init(&sa));

  // Ask for SIGALRM to be defaulted in the child...
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);

  ASSERT_EQ(0, posix_spawnattr_setsigdefault(&sa, &just_SIGALRM));
  ASSERT_EQ(0, posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGDEF));

  // Check that's what happens...
  ProcStatus ps = {};
  GetChildStatus(&sa, &ps);

  // TIMER_SIGNAL should be blocked.
  uint64_t expected_blocked = 0;
  SignalSetAdd(&expected_blocked, BIONIC_SIGNAL_POSIX_TIMERS);
  EXPECT_EQ(expected_blocked, ps.sigblk);

  uint64_t expected_ignored = 0;
  SignalSetAdd(&expected_ignored, SIGCONT);
  SignalSetAdd(&expected_ignored, BIONIC_SIGNAL_ART_PROFILER);
  EXPECT_EQ(expected_ignored, ps.sigign);

  ASSERT_EQ(0, posix_spawnattr_destroy(&sa));
#endif
}

TEST(spawn, signal_stress) {
  // Ensure that posix_spawn doesn't restore the caller's signal mask in the
  // child without first defaulting any caught signals (http://b/68707996).
  static pid_t parent = getpid();

  setpgid(0, 0);
  signal(SIGRTMIN, SIG_IGN);

  pid_t pid = fork();
  ASSERT_NE(-1, pid);

  if (pid == 0) {
    for (size_t i = 0; i < 1024; ++i) {
      kill(0, SIGRTMIN);
      usleep(10);
    }
    _exit(99);
  }

  // We test both with and without attributes, because they used to be
  // different codepaths. We also test with an empty `sigdefault` set.
  posix_spawnattr_t attr1;
  posix_spawnattr_init(&attr1);

  sigset_t empty_mask = {};
  posix_spawnattr_t attr2;
  posix_spawnattr_init(&attr2);
  posix_spawnattr_setflags(&attr2, POSIX_SPAWN_SETSIGDEF);
  posix_spawnattr_setsigdefault(&attr2, &empty_mask);

  posix_spawnattr_t* attrs[] = { nullptr, &attr1, &attr2 };

  // We use a real-time signal because that's a tricky case for LP32
  // because our sigset_t was too small.
  ScopedSignalHandler ssh(SIGRTMIN, [](int) { ASSERT_EQ(getpid(), parent); });

  const size_t pid_count = 128;
  pid_t spawned_pids[pid_count];

  ExecTestHelper eth;
  eth.SetArgs({"true", nullptr});
  for (size_t i = 0; i < pid_count; ++i) {
    pid_t spawned_pid;
    ASSERT_EQ(0, posix_spawn(&spawned_pid, "true", nullptr, attrs[i % 3], eth.GetArgs(), nullptr));
    spawned_pids[i] = spawned_pid;
  }

  for (pid_t spawned_pid : spawned_pids) {
    ASSERT_EQ(spawned_pid, TEMP_FAILURE_RETRY(waitpid(spawned_pid, nullptr, 0)));
  }

  AssertChildExited(pid, 99);
}

TEST(spawn, posix_spawn_dup2_CLOEXEC) {
  int fds[2];
  ASSERT_NE(-1, pipe(fds));

  posix_spawn_file_actions_t fa;
  ASSERT_EQ(0, posix_spawn_file_actions_init(&fa));

  int fd = open("/proc/version", O_RDONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);

  ASSERT_EQ(0, posix_spawn_file_actions_addclose(&fa, fds[0]));
  ASSERT_EQ(0, posix_spawn_file_actions_adddup2(&fa, fds[1], 1));
  // dup2() is a no-op when the two fds are the same, so this won't clear
  // O_CLOEXEC unless we're doing extra work to make that happen.
  ASSERT_EQ(0, posix_spawn_file_actions_adddup2(&fa, fd, fd));

  // Read /proc/self/fd/<fd> in the child...
  std::string fdinfo_path = android::base::StringPrintf("/proc/self/fd/%d", fd);
  ExecTestHelper eth;
  eth.SetArgs({"cat", fdinfo_path.c_str(), nullptr});
  pid_t pid;
  ASSERT_EQ(0, posix_spawnp(&pid, eth.GetArg0(), &fa, nullptr, eth.GetArgs(), eth.GetEnv()));
  ASSERT_EQ(0, posix_spawn_file_actions_destroy(&fa));
  ASSERT_EQ(0, close(fds[1]));
  std::string content;
  ASSERT_TRUE(android::base::ReadFdToString(fds[0], &content));
  ASSERT_EQ(0, close(fds[0]));

  // ...and compare that to the parent. This is overkill really, since the very
  // fact that the child had a valid file descriptor strongly implies that we
  // removed O_CLOEXEC, but we may as well check that the child ended up with
  // the *right* file descriptor :-)
  std::string expected;
  ASSERT_TRUE(android::base::ReadFdToString(fd, &expected));
  ASSERT_EQ(expected, content);

  AssertChildExited(pid, 0);
}

"""

```