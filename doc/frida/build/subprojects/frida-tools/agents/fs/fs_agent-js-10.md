Response:
Let's break down the thought process for analyzing this Frida script.

**1. Initial Impression & Context:**

The first thing I noticed is the header: `这是目录为frida/build/subprojects/frida-tools/agents/fs/fs_agent.js的frida Dynamic instrumentation tool的源代码文件`. This immediately tells me:

* **Technology:** Frida (dynamic instrumentation).
* **Purpose:**  File system related operations.
* **Location:** Likely part of a larger Frida toolkit.
* **Language:** JavaScript.

**2. Code Structure and Key Components:**

I started scanning the code for recognizable patterns and keywords:

* **`import` statements:**  `buffer`, `path`, `process`, `stream`. This indicates interaction with Node.js core modules, suggesting file system operations (path manipulation, streams).
* **`pt((function(){return ft(...)})), ...`:** This pattern repeats. It looks like some kind of helper function (`pt` and `ft`) used to define platform-specific system calls. The presence of `CreateFileW`, `DeleteFileW`, `ReadFile` (Windows) and `open`, `close`, `read`, `unlink` (likely Linux/macOS) confirms the file system focus and platform abstraction.
* **Class definitions:** `h extends c.Readable`, `_ extends c.Writable`. These clearly indicate the creation of readable and writable streams, core for file I/O.
* **Object `U` (Windows) and `w` (Unix-like):** These objects contain functions like `enumerateDirectoryEntries`, `readFileSync`, `readlinkSync`, `rmdirSync`, `unlinkSync`, `statSync`, `lstatSync`. These are standard file system operations. The platform split reinforces the idea of handling OS differences.
* **Helper functions:** `F` (likely for encoding handling), `K` (for creating `Stats` objects), `et` and `nt` (for throwing errors), `ot` (for asynchronous wrappers).
* **Constants:** The `S` object holds various file system flags and constants (e.g., `O_RDONLY`, `S_IFREG`).
* **Exports:**  The `export` statements at the end list the functions made available by this module (e.g., `createReadStream`, `readFile`, `readdir`, `stat`).

**3. Functionality Deduction (High-Level):**

Based on the identified components, I could deduce the main functionalities:

* **File Reading:**  `createReadStream`, `readFileSync`.
* **File Writing:** `createWriteStream`, `writeFileSync`.
* **Directory Operations:** `readdir`, `readdirSync`, `enumerateDirectoryEntries`.
* **File/Directory Manipulation:** `rmdir`, `rmdirSync`, `unlink`, `unlinkSync`.
* **File Information:** `stat`, `statSync`, `lstat`, `lstatSync`,  the `Stats` class.
* **Symbolic Links:** `readlink`, `readlinkSync`.
* **Platform Abstraction:** The distinct code paths for Windows and Unix-like systems.

**4. Binary/Kernel/OS Interactions:**

The presence of `NativeFunction` and system call names (like `CreateFileW`, `open`) directly points to interaction with the operating system's kernel-level APIs.

* **Windows Examples:** `CreateFileW` is a Win32 API call for creating or opening files/devices. `ReadFile` reads data from a file. `DeleteFileW` removes a file.
* **Linux/macOS Examples:** `open` is a system call for opening files. `read` reads data. `unlink` removes a file. `stat` and `lstat` retrieve file/directory metadata.

The code uses `Memory.alloc` and `Memory.allocUtf16String`/`Memory.allocUtf8String` to allocate memory for arguments passed to these native functions.

**5. Debugging Functionality & `lldb` Equivalents:**

Since this *is* a Frida agent, it's designed for *dynamic instrumentation*, meaning it *is* the debugging tool itself. Therefore, the `lldb` examples focus on how you *could* potentially replicate its behavior at a lower level *if* you weren't using Frida.

* **Setting breakpoints:**  Break at the entry point of the native functions being called (e.g., `kernel32!CreateFileW` or `libc.so!open`).
* **Examining arguments:** Inspect the parameters passed to the system calls (file paths, flags, etc.).
* **Examining return values:** Check the results of the system calls (file handles, error codes).
* **Scripting with `lldb` Python:** Automating these steps, similar to how the Frida agent automates hooking and data extraction.

**6. Logic Reasoning, Assumptions, and User Errors:**

* **Assumptions:** The code assumes the target process has the necessary permissions to perform the file system operations.
* **Logic:** The platform detection logic determines which set of system calls to use. Error handling is present (throwing errors on failed system calls).
* **User Errors:**  Common issues involve:
    * **Incorrect file paths:**  The file or directory doesn't exist.
    * **Permission issues:** The process lacks the rights to access the file or directory.
    * **Incorrect flags:** Using inappropriate flags when opening files.

**7. User Operations to Reach the Code:**

I considered the user's perspective: How would someone trigger this code within a Frida context?

* **Frida Script Usage:** A user would write a Frida script that uses the `Frida.紮根程式()` API to attach to a process.
* **Agent Injection:** The `fs_agent.js` file is part of the agent that gets loaded into the target process.
* **API Calls:** The user's Frida script would then call the functions exported by this module (e.g., `Frida.紮根程式().檔案系統.readFile("/path/to/file")`).

**8. Summarization (Final Step):**

The final step was to condense the analyzed information into a concise summary of the script's functionalities, emphasizing its role as a Frida-based tool for file system interaction. I focused on the key operations it enables and its platform-aware nature.

**Self-Correction/Refinement during the process:**

* Initially, I might have just seen the `import` statements and thought "file system stuff." But then, recognizing the platform-specific code and the system call names helped me understand the deeper interaction with the OS.
* I realized that since this *is* a debugging/instrumentation tool, the "debugging functionality" question is answered by the code itself. The `lldb` examples needed to be reframed as *alternative* ways to achieve similar low-level inspection.
* I made sure to provide concrete examples for each point, especially for the binary/kernel interactions and user errors.这是一个Frida动态 instrumentation工具的JavaScript源代码文件，位于`frida/build/subprojects/frida-tools/agents/fs/fs_agent.js`目录下。这意味着它是Frida工具集中用于文件系统操作的代理（agent）。

**主要功能归纳:**

这个Frida Agent的主要功能是**允许用户通过Frida在目标进程中动态地监控和操作文件系统**。它提供了类似于Node.js `fs`模块的API，但操作的是目标进程的文件系统。

**详细功能列举:**

1. **文件读取:**
   - `createReadStream(path)`: 创建一个可读的文件流。
   - `readFileSync(path, options)`: 同步读取文件的全部内容。
   - `readFile(path, options, callback)`: 异步读取文件的全部内容。

2. **文件写入:**
   - `createWriteStream(path)`: 创建一个可写的文件流。
   - `writeFileSync(path, data, options)`: 同步写入数据到文件。
   - `writeFile(path, data, options, callback)`: 异步写入数据到文件。

3. **目录操作:**
   - `readdir(path, options, callback)`: 异步读取目录中的文件和子目录名。
   - `readdirSync(path, options)`: 同步读取目录中的文件和子目录名。
   - `list(path)`:  列出目录中的文件和子目录的详细信息（名称、类型等）。
   - `enumerateDirectoryEntries(path, entryCallback)`: 底层遍历目录条目的函数。

4. **链接操作:**
   - `readlink(path, callback)`: 异步读取符号链接的目标。
   - `readlinkSync(path)`: 同步读取符号链接的目标。

5. **删除操作:**
   - `rmdir(path, callback)`: 异步删除目录。
   - `rmdirSync(path)`: 同步删除目录。
   - `unlink(path, callback)`: 异步删除文件。
   - `unlinkSync(path)`: 同步删除文件。

6. **文件/目录信息:**
   - `stat(path, callback)`: 异步获取文件或目录的状态信息（如大小、权限、修改时间等）。
   - `statSync(path)`: 同步获取文件或目录的状态信息。
   - `lstat(path, callback)`: 异步获取文件或目录的状态信息，不跟随符号链接。
   - `lstatSync(path)`: 同步获取文件或目录的状态信息，不跟随符号链接。
   - `Stats` 类:  表示文件/目录状态信息的类。

7. **常量:**
   - `constants`: 提供各种文件系统相关的常量，例如 `O_RDONLY` (只读模式), `S_IFREG` (普通文件类型) 等，这些常量在不同的操作系统上可能会有不同的值。

**涉及二进制底层，Linux内核的举例说明:**

* **底层系统调用:** 代码中直接使用了底层的系统调用，例如：
    * **Windows:** `CreateFileW`, `DeleteFileW`, `ReadFile`, `RemoveDirectoryW`, `CloseHandle`, `FindFirstFileW`, `FindNextFileW`, `FindClose`, `GetFileAttributesExW`, `GetFinalPathNameByHandleW`, `FormatMessageW`。 这些都是Windows API，直接与Windows内核交互。
    * **Linux/macOS:** `open`, `close`, `lseek`, `read`, `opendir`, `closedir`, `readdir`, `readlink`, `rmdir`, `unlink`, `stat`, `stat64`, `__xstat64`, `lstat`, `lstat64`, `__lxstat64`, `strerror`。 这些是POSIX标准的系统调用，直接与Linux内核或macOS内核交互。

    **举例 (Linux):** `d().open(Memory.allocUtf8String(n), S.O_RDONLY, 0)` 这行代码调用了 `open` 系统调用来打开文件。 `Memory.allocUtf8String(n)` 将 JavaScript 的字符串路径转换为 C 风格的 UTF-8 字符串，这是系统调用所要求的格式。 `S.O_RDONLY` 是一个常量，表示以只读模式打开文件。

* **文件描述符:** 在Linux/macOS部分，代码使用文件描述符 (`int`) 来标识打开的文件。例如，`UnixInputStream` 和 `UnixOutputStream` 类接收文件描述符作为参数。

* **文件状态结构体:** `stat` 和 `lstat` 函数返回的文件状态信息 (`Stats` 类) 对应于操作系统底层的 `stat` 结构体 (在Linux中是 `struct stat`)，包含了文件的各种元数据。

**用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例 (如果源代码是调试功能的实现):**

由于这个源代码本身就是一个Frida Agent，它的主要目的是**提供调试和instrumentation功能**。因此，我们无法直接用 `lldb` 复刻它 *全部* 的功能，因为 Frida 提供了动态注入代码和拦截函数的能力，这是 `lldb` 本身不具备的。

但是，我们可以用 `lldb` 来 **观察** 目标进程在执行这些文件系统操作时的行为，从而理解 Frida Agent 所做的事情。

**假设我们想观察目标进程在执行 `fs_agent.js` 中的 `readFileSync` 时，实际调用的 `open` 系统调用 (在 Linux 上):**

1. **在目标进程启动后，找到 `open` 系统调用的地址:**
   ```lldb
   (lldb) image lookup -s open
   ```
   这会列出 `open` 符号及其地址。

2. **设置断点在 `open` 系统调用的入口:**
   假设 `open` 的地址是 `0x7ffff7b804b0`。
   ```lldb
   (lldb) b *0x7ffff7b804b0
   ```

3. **运行目标进程，并让 Frida Agent 执行 `readFileSync` 操作。**  这可以通过编写一个 Frida 脚本，调用 `紮根程式().檔案系統.readFileSync()` 来实现。

4. **当断点命中时，查看 `open` 系统调用的参数:**
   在 `x86_64` Linux 上，`open` 的参数通常通过寄存器传递 (例如，第一个参数路径在 `rdi` 中，第二个参数标志在 `rsi` 中)。
   ```lldb
   (lldb) p/s $rdi  // 查看文件路径
   (lldb) p/x $rsi  // 查看打开标志
   ```
   这将显示 `readFileSync` 尝试打开的文件的路径以及打开的模式 (例如，`0` 代表只读)。

5. **查看 `open` 系统调用的返回值:**
   系统调用的返回值通常存储在 `rax` 寄存器中。成功时，它是一个非负的文件描述符；失败时，它是 `-1`。
   ```lldb
   (lldb) p $rax
   ```

**用lldb python脚本复刻 `readFileSync` 部分功能的示例 (Linux):**

```python
import lldb
import os

def read_file_lldb(debugger, command, result, internal_dict):
    args = command.split()
    if len(args) != 1:
        result.SetError("Usage: read_file_lldb <filepath>")
        return

    filepath = args[0]

    # 获取 open 系统调用的地址
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    open_symbol = target.FindFirstSymbol("open")
    if not open_symbol.IsValid():
        result.SetError("Could not find 'open' symbol.")
        return
    open_addr = open_symbol.GetAddress().GetLoadAddress(target)

    # 设置断点
    breakpoint = process.CreateBreakpoint(lldb.SBAddress(open_addr))

    # 设置断点命中时的回调
    def breakpoint_callback(frame, bp_loc, dict):
        # 读取 open 的参数
        rdi_val = frame.FindRegister("rdi").GetValueAsUnsigned()
        rsi_val = frame.FindRegister("rsi").GetValueAsUnsigned()

        # 从内存中读取路径字符串
        error = lldb.SBError()
        path_ptr = target.ReadPointerFromMemory(rdi_val, error)
        if error.Fail():
            print("Error reading path pointer:", error)
            return

        path_str = process.ReadCStringFromMemory(path_ptr, 256, error) # 假设最大路径长度为 256
        if error.Fail():
            print("Error reading path string:", error)
            return

        print(f"open called with path: {path_str}, flags: {rsi_val:#x}")

        # 继续执行
        process.Continue()
        return True

    breakpoint.SetScriptCallbackFunction(breakpoint_callback)

    # 继续执行进程
    process.Continue()

    # (在实际使用中，你需要让目标进程执行到调用 readFileSync 的地方)

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f read_file_lldb read_file_lldb')
    print("The 'read_file_lldb' command has been installed.")
```

**使用方法:**

1. 将上述 Python 脚本保存为 `read_file.py`。
2. 在 `lldb` 中加载该脚本： `(lldb) command source read_file.py`
3. 使用 `read_file_lldb` 命令，例如： `(lldb) read_file_lldb /path/to/your/file.txt`
4. 运行你的目标进程。当目标进程调用 `open` 系统调用尝试打开指定的文件时，lldb 会中断并打印相关信息。

**请注意:** 这个 `lldb` 脚本只是一个简化的示例，用于观察 `open` 系统调用。要完全复刻 `readFileSync` 的功能，你需要处理后续的 `read` 系统调用，内存分配，以及文件内容的读取和处理。

**逻辑推理的假设输入与输出 (以 `readFileSync` 为例):**

**假设输入:**

* `path`: "/tmp/test.txt"
* 文件 "/tmp/test.txt" 的内容是 "Hello, Frida!"
* `options`:  (空，表示默认的 UTF-8 编码)

**预期输出:**

* 函数 `readFileSync` 返回字符串 "Hello, Frida!"

**假设输入 (包含编码选项):**

* `path`: "/tmp/test.txt"
* 文件 "/tmp/test.txt" 的内容是包含特定编码字符的二进制数据。
* `options`: { encoding: "latin1" }

**预期输出:**

* 函数 `readFileSync` 返回根据 "latin1" 编码解析后的字符串。

**涉及用户或者编程常见的使用错误，举例说明:**

1. **路径错误:** 用户提供的文件路径不存在或不正确。
   ```javascript
   // 错误的路径
   Frida.紮根程式().檔案系統.readFileSync("/non/existent/file.txt");
   // 错误信息可能类似于 "Error: ENOENT: no such file or directory, open '/non/existent/file.txt'"
   ```

2. **权限错误:** 目标进程没有读取或写入文件的权限。
   ```javascript
   // 尝试读取一个只有 root 用户才能读取的文件
   Frida.紮根程式().檔案系統.readFileSync("/etc/shadow");
   // 错误信息可能类似于 "Error: EACCES: permission denied, open '/etc/shadow'"
   ```

3. **尝试在目录上进行文件操作:** 用户尝试使用文件操作函数 (如 `readFileSync`) 操作一个目录。
   ```javascript
   // 尝试读取一个目录
   Frida.紮根程式().檔案系統.readFileSync("/tmp");
   // 错误信息可能类似于 "Error: EISDIR: illegal operation on a directory, read"
   ```

4. **编码问题:** 使用 `readFileSync` 时，如果文件编码与指定的编码选项不匹配，可能会导致乱码或解析错误。

5. **异步操作未正确处理回调:** 对于异步函数 (如 `readFile`), 用户如果没有正确处理回调函数，可能会导致程序逻辑错误或未捕获的异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户编写一个 JavaScript 文件，其中使用了 Frida 的 `紮根程式()` API 来连接到目标进程。
2. **用户获取文件系统 API:** 用户通过 `紮根程式().檔案系統` 获取了目标进程的文件系统操作 API。
3. **用户调用文件系统函数:** 用户在 Frida 脚本中调用了 `檔案系統` 提供的函数，例如 `readFileSync("/path/to/file")`。
4. **Frida 将调用传递给 Agent:** Frida 框架会将这个 JavaScript 调用转发到注入到目标进程的 `fs_agent.js` 代码中。
5. **Agent 执行操作:** `fs_agent.js` 中的相应函数 (例如 `readFileSync`) 会被执行，它会调用底层的系统调用来完成文件系统操作。

**调试线索:**

当出现文件系统相关的错误时，可以按照以下步骤进行调试：

1. **检查 Frida 脚本中的路径:** 确认提供的文件或目录路径是否正确。
2. **检查目标进程的权限:** 确认目标进程是否有权限执行所需的文件系统操作。可以使用 `stat` 或 `lstat` 来检查文件权限。
3. **查看错误信息:** Frida Agent 通常会抛出包含详细错误信息的异常，仔细阅读错误信息可以帮助定位问题。
4. **使用 `lldb` 或其他调试器:** 可以将 `lldb` 连接到目标进程，设置断点在相关的系统调用入口，观察参数和返回值，以了解底层发生了什么。
5. **检查文件编码:** 如果涉及到文本文件的读取，确认指定的编码选项是否正确。
6. **对于异步操作，检查回调函数:** 确保异步操作的回调函数被正确定义和处理。

**这是第11部分，共12部分，请归纳一下它的功能:**

作为12部分中的第11部分，这个 `fs_agent.js` 文件是整个Frida文件系统支持的核心实现。它提供了**在目标进程中模拟Node.js `fs` 模块功能的关键逻辑**。之前的模块可能定义了接口或者更高层次的抽象，而这个模块则负责将这些抽象转化为实际的操作系统级别的文件系统操作。接下来的第12部分很可能是对这个模块进行注册、导出或与其他Frida组件进行整合的代码。

总而言之，`fs_agent.js` 的功能是**为 Frida 提供在目标进程中进行精细的文件系统动态 instrumentation 能力**，是 Frida 文件系统支持的重要组成部分。

### 提示词
```
这是目录为frida/build/subprojects/frida-tools/agents/fs/fs_agent.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第11部分，共12部分，请归纳一下它的功能
```

### 源代码
```javascript
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"}
✄
var t,e,n,r,i=this&&this.__classPrivateFieldSet||function(t,e,n,r,i){if("m"===r)throw new TypeError("Private method is not writable");if("a"===r&&!i)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===r?i.call(t,n):i?i.value=n:e.set(t,n),n},o=this&&this.__classPrivateFieldGet||function(t,e,n,r){if("a"===n&&!r)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!r:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===n?r:"a"===n?r.call(t):r?r.value:e.get(t)};import{Buffer as l}from"buffer";import s from"path";import a from"process";import c from"stream";const u=pt((function(){return ft([["CreateFileW",lt,"pointer",["pointer","uint","uint","pointer","uint","uint","pointer"]],["DeleteFileW",lt,"uint",["pointer"]],["GetFileSizeEx",lt,"uint",["pointer","pointer"]],["ReadFile",lt,"uint",["pointer","pointer","uint","pointer","pointer"]],["RemoveDirectoryW",lt,"uint",["pointer"]],["CloseHandle",st,"uint",["pointer"]],["FindFirstFileW",lt,"pointer",["pointer","pointer"]],["FindNextFileW",st,"uint",["pointer","pointer"]],["FindClose",st,"uint",["pointer"]],["GetFileAttributesExW",lt,"uint",["pointer","uint","pointer"]],["GetFinalPathNameByHandleW",lt,"uint",["pointer","pointer","uint","uint"]],["FormatMessageW",st,"uint",["uint","pointer","uint","uint","pointer","uint","pointer"]]])})),d=pt((function(){return ft([["open",lt,"int",["pointer","int","...","int"]],["close",st,"int",["int"]],["lseek",st,ut,["int",ut,"int"]],["read",lt,at,["int","pointer",ct]],["opendir",lt,"pointer",["pointer"]],["opendir$INODE64",lt,"pointer",["pointer"]],["closedir",st,"int",["pointer"]],["readdir",st,"pointer",["pointer"]],["readdir$INODE64",st,"pointer",["pointer"]],["readlink",lt,at,["pointer","pointer",ct]],["rmdir",lt,"int",["pointer"]],["unlink",lt,"int",["pointer"]],["stat",lt,"int",["pointer","pointer"]],["stat64",lt,"int",["pointer","pointer"]],["__xstat64",lt,"int",["int","pointer","pointer"],dt],["lstat",lt,"int",["pointer","pointer"]],["lstat64",lt,"int",["pointer","pointer"]],["__lxstat64",lt,"int",["int","pointer","pointer"],dt],["strerror",st,"pointer",["int"]]])})),{platform:f,pointerSize:m}=Process,p="windows"===f,S={...{S_IFMT:61440,S_IFREG:32768,S_IFDIR:16384,S_IFCHR:8192,S_IFBLK:24576,S_IFIFO:4096,S_IFLNK:40960,S_IFSOCK:49152,S_IRWXU:448,S_IRUSR:256,S_IWUSR:128,S_IXUSR:64,S_IRWXG:56,S_IRGRP:32,S_IWGRP:16,S_IXGRP:8,S_IRWXO:7,S_IROTH:4,S_IWOTH:2,S_IXOTH:1,DT_UNKNOWN:0,DT_FIFO:1,DT_CHR:2,DT_DIR:4,DT_BLK:6,DT_REG:8,DT_LNK:10,DT_SOCK:12,DT_WHT:14},...{darwin:{O_RDONLY:0,O_WRONLY:1,O_RDWR:2,O_CREAT:512,O_EXCL:2048,O_NOCTTY:131072,O_TRUNC:1024,O_APPEND:8,O_DIRECTORY:1048576,O_NOFOLLOW:256,O_SYNC:128,O_DSYNC:4194304,O_SYMLINK:2097152,O_NONBLOCK:4},linux:{O_RDONLY:0,O_WRONLY:1,O_RDWR:2,O_CREAT:64,O_EXCL:128,O_NOCTTY:256,O_TRUNC:512,O_APPEND:1024,O_DIRECTORY:65536,O_NOATIME:262144,O_NOFOLLOW:131072,O_SYNC:1052672,O_DSYNC:4096,O_DIRECT:16384,O_NONBLOCK:2048}}[f]},y=ptr(-1);class h extends c.Readable{constructor(n){if(super({highWaterMark:4194304}),t.set(this,null),e.set(this,null),p){const e=u().CreateFileW(Memory.allocUtf16String(n),2147483648,1,NULL,3,1073741824,NULL),r=e.value;if(r.equals(y))return void a.nextTick((()=>{this.destroy(rt(e.lastError))}));i(this,t,new Win32InputStream(r,{autoClose:!0}),"f")}else{const e=d().open(Memory.allocUtf8String(n),S.O_RDONLY,0),r=e.value;if(-1===r)return void a.nextTick((()=>{this.destroy(it(e.errno))}));i(this,t,new UnixInputStream(r,{autoClose:!0}),"f")}}_destroy(e,n){o(this,t,"f")?.close(),i(this,t,null,"f"),n(e)}_read(n){null===o(this,e,"f")&&i(this,e,o(this,t,"f").read(n).then((t=>{i(this,e,null,"f"),0!==t.byteLength?this.push(l.from(t))&&this._read(n):this.push(null)})).catch((t=>{i(this,e,null,"f"),this.destroy(t)})),"f")}}t=new WeakMap,e=new WeakMap;class _ extends c.Writable{constructor(t){if(super({highWaterMark:4194304}),n.set(this,null),r.set(this,null),p){const e=u().CreateFileW(Memory.allocUtf16String(t),1073741824,0,NULL,2,1073741952,NULL),r=e.value;if(r.equals(y))return void a.nextTick((()=>{this.destroy(rt(e.lastError))}));i(this,n,new Win32OutputStream(r,{autoClose:!0}),"f")}else{const e=d(),r=Memory.allocUtf8String(t),o=S.O_WRONLY|S.O_CREAT|S.O_TRUNC,l=S.S_IRUSR|S.S_IWUSR|S.S_IRGRP|S.S_IROTH,s=e.open(r,o,l),c=s.value;if(-1===c)return void a.nextTick((()=>{this.destroy(it(s.errno))}));i(this,n,new UnixOutputStream(c,{autoClose:!0}),"f")}}_destroy(t,e){o(this,n,"f")?.close(),i(this,n,null,"f"),e(t)}_write(t,e,l){null===o(this,r,"f")&&i(this,r,o(this,n,"f").writeAll(t).then((t=>{i(this,r,null,"f"),l()})).catch((t=>{i(this,r,null,"f"),l(t)})),"f")}}n=new WeakMap,r=new WeakMap;const U={enumerateDirectoryEntries(t,e){O(t+"\\*",e)},readFileSync(t,e={}){"string"==typeof e&&(e={encoding:e});const{encoding:n=null}=e,{CreateFileW:r,GetFileSizeEx:i,ReadFile:o,CloseHandle:l}=u(),s=r(Memory.allocUtf16String(t),2147483648,1,NULL,3,0,NULL),a=s.value;a.equals(y)&&et(s.lastError);try{const t=Memory.alloc(8),e=t,r=i(a,e);0===r.value&&et(r.lastError);const s=e.readU64().valueOf(),c=Memory.alloc(s),u=t,d=o(a,c,s,u,NULL);0===d.value&&et(d.lastError);if(u.readU32()!==s)throw new Error("Short read");return F(c,s,n)}finally{l(a)}},readlinkSync(t){const{CreateFileW:e,GetFinalPathNameByHandleW:n,CloseHandle:r}=u(),i=e(Memory.allocUtf16String(t),0,7,NULL,3,33554432,NULL),o=i.value;o.equals(y)&&et(i.lastError);try{let t=256;for(;;){const e=Memory.alloc(2*t),{value:r,lastError:i}=n(o,e,t,0);if(0===r&&et(i),8!==i)return e.readUtf16String().substring(4);t*=2}}finally{r(o)}},rmdirSync(t){const e=u().RemoveDirectoryW(Memory.allocUtf16String(t));0===e.value&&et(e.lastError)},unlinkSync(t){const e=u().DeleteFileW(Memory.allocUtf16String(t));0===e.value&&et(e.lastError)},statSync(t){const e=U.lstatSync(t);if(!e.isSymbolicLink())return e;const n=U.readlinkSync(t);return U.lstatSync(n)},lstatSync(t){const e=Memory.alloc(36),n=u().GetFileAttributesExW(Memory.allocUtf16String(t),0,e);if(0===n.value){if(32===n.lastError){let e;return O(t,(t=>{e=Memory.dup(t,36)})),K(t,e)}et(n.lastError)}return K(t,e)}};function O(t,e){const{FindFirstFileW:n,FindNextFileW:r,FindClose:i}=u(),o=Memory.alloc(592),l=n(Memory.allocUtf16String(t),o),s=l.value;s.equals(y)&&et(l.lastError);try{do{e(o)}while(0!==r(s,o))}finally{i(s)}}const w={enumerateDirectoryEntries(t,e){const{opendir:n,opendir$INODE64:r,closedir:i,readdir:o,readdir$INODE64:l}=d(),s=l||o,a=(r||n)(Memory.allocUtf8String(t)),c=a.value;c.isNull()&&nt(a.errno);try{let t;for(;!(t=s(c)).isNull();)e(t)}finally{i(c)}},readFileSync(t,e={}){"string"==typeof e&&(e={encoding:e});const{encoding:n=null}=e,{open:r,close:i,lseek:o,read:l}=d(),s=r(Memory.allocUtf8String(t),S.O_RDONLY,0),a=s.value;-1===a&&nt(s.errno);try{const t=o(a,0,2).valueOf();o(a,0,0);const e=Memory.alloc(t);let r,s,c;do{r=l(a,e,t),s=r.value.valueOf(),c=-1===s}while(c&&4===r.errno);if(c&&nt(r.errno),s!==t.valueOf())throw new Error("Short read");return F(e,t,n)}finally{i(a)}},readlinkSync(t){const e=Memory.allocUtf8String(t),n=w.lstatSync(t).size.valueOf(),r=Memory.alloc(n),i=d().readlink(e,r,n),o=i.value.valueOf();return-1===o&&nt(i.errno),r.readUtf8String(o)},rmdirSync(t){const e=d().rmdir(Memory.allocUtf8String(t));-1===e.value&&nt(e.errno)},unlinkSync(t){const e=d().unlink(Memory.allocUtf8String(t));-1===e.value&&nt(e.errno)},statSync:t=>g(A()._stat,t),lstatSync:t=>g(A()._lstat,t)};function v(t,e,n={}){"string"==typeof n&&(n={encoding:n});const{encoding:r=null}=n;let i;i="string"==typeof e?null===r||k(r)?e:l.from(e,r).buffer:e.buffer;const o=new File(t,"wb");try{o.write(i)}finally{o.close()}}function g(t,e){const n=Memory.alloc(H),r=t(Memory.allocUtf8String(e),n);return 0!==r.value&&nt(r.errno),K(e,n)}function F(t,e,n){if(k(n))return t.readUtf8String(e);const r=l.from(t.readByteArray(e));return null!==n?r.toString(n):r}function k(t){return"utf8"===t||"utf-8"===t}const N=p?U:w,{enumerateDirectoryEntries:R,readFileSync:b,readlinkSync:E,rmdirSync:W,unlinkSync:I,statSync:L,lstatSync:M}=N,x={windows:{d_name:[44,"Utf16String"],d_type:[0,j],atime:[12,q],mtime:[20,q],ctime:[4,q],size:[28,J]},"linux-32":{d_name:[11,"Utf8String"],d_type:[10,"U8"]},"linux-64":{d_name:[19,"Utf8String"],d_type:[18,"U8"]},"darwin-32":{d_name:[21,"Utf8String"],d_type:[20,"U8"]},"darwin-64":{d_name:[21,"Utf8String"],d_type:[20,"U8"]}},D=p?x.windows:x[`${f}-${8*m}`];function C(t){const e=[];return R(t,(t=>{const n=z(t,"d_name");e.push(n)})),e}function T(t){const e=Object.keys(D).filter((t=>!t.startsWith("d_"))),n=[];return R(t,(r=>{const i=z(r,"d_name"),o=z(r,"d_type",s.join(t,i)),l={};for(const t of e)l[t]=z(r,t);n.push({name:i,type:o,...l})})),n}function z(t,e,...n){const r=D[e],[i,o]=r,l=("string"==typeof o?NativePointer.prototype["read"+o]:o).call(t.add(i),...n);return l instanceof Int64||l instanceof UInt64?l.valueOf():l}const P=new Set(["dev","mode","nlink","uid","gid","rdev","blksize","ino","size","blocks","atimeMs","mtimeMs","ctimeMs","birthtimeMs","atime","mtime","ctime","birthtime"]),Y={windows:{size:36,fields:{dev:[0,Z],mode:[0,j],nlink:[0,tt],ino:[0,Z],uid:[0,Z],gid:[0,Z],rdev:[0,Z],atime:[12,q],mtime:[20,q],ctime:[20,q],birthtime:[4,q],size:[28,J],blocks:[28,J],blksize:[0,tt]}},"darwin-32":{size:108,fields:{dev:[0,"S32"],mode:[4,"U16"],nlink:[6,"U16"],ino:[8,"U64"],uid:[16,"U32"],gid:[20,"U32"],rdev:[24,"S32"],atime:[28,Q],mtime:[36,Q],ctime:[44,Q],birthtime:[52,Q],size:[60,"S64"],blocks:[68,"S64"],blksize:[76,"S32"]}},"darwin-64":{size:144,fields:{dev:[0,"S32"],mode:[4,"U16"],nlink:[6,"U16"],ino:[8,"U64"],uid:[16,"U32"],gid:[20,"U32"],rdev:[24,"S32"],atime:[32,V],mtime:[48,V],ctime:[64,V],birthtime:[80,V],size:[96,"S64"],blocks:[104,"S64"],blksize:[112,"S32"]}},"linux-32":{size:88,fields:{dev:[0,"U64"],mode:[16,"U32"],nlink:[20,"U32"],ino:[12,"U32"],uid:[24,"U32"],gid:[28,"U32"],rdev:[32,"U64"],atime:[56,Q],mtime:[64,Q],ctime:[72,Q],size:[44,"S32"],blocks:[52,"S32"],blksize:[48,"S32"]}},"linux-32-stat64":{size:104,fields:{dev:[0,"U64"],mode:[16,"U32"],nlink:[20,"U32"],ino:[96,"U64"],uid:[24,"U32"],gid:[28,"U32"],rdev:[32,"U64"],atime:[72,Q],mtime:[80,Q],ctime:[88,Q],size:[48,"S64"],blocks:[64,"S64"],blksize:[56,"S32"]}},"linux-64":{size:144,fields:{dev:[0,"U64"],mode:[24,"U32"],nlink:[16,"U64"],ino:[8,"U64"],uid:[28,"U32"],gid:[32,"U32"],rdev:[40,"U64"],atime:[72,V],mtime:[88,V],ctime:[104,V],size:[48,"S64"],blocks:[64,"S64"],blksize:[56,"S64"]}}};let G=null;const H=256;function A(){if(null!==G)return G;let t;if(p)t=Y.windows;else{const e=d(),n=e.stat64??e.__xstat64;let r=`${f}-${8*m}`;if("linux-32"===r&&void 0!==n&&(r+="-stat64"),t=Y[r],void 0===t)throw new Error("Current OS is not yet supported; please open a PR");t._stat=n??e.stat,t._lstat=e.lstat64??e.__lxstat64??e.lstat}return G=t,t}class B{isFile(){return 32768==(61440&this.mode)}isDirectory(){return 16384==(61440&this.mode)}isCharacterDevice(){return 8192==(61440&this.mode)}isBlockDevice(){return 24576==(61440&this.mode)}isFIFO(){return 4096==(61440&this.mode)}isSymbolicLink(){return 40960==(61440&this.mode)}isSocket(){return 49152==(61440&this.mode)}}function K(t,e){return new Proxy(new B,{has:(t,e)=>"symbol"==typeof e?e in t:X(e),get(n,r,i){switch(r){case"prototype":return;case"constructor":case"toString":return n[r];case"hasOwnProperty":return X;case"valueOf":return i;case"buffer":return e;default:return"symbol"==typeof r||r in n?n[r]:$.call(i,r,t)}},set:(t,e,n,r)=>!1,ownKeys:t=>Array.from(P),getOwnPropertyDescriptor:(t,e)=>({writable:!1,configurable:!0,enumerable:!0})})}function X(t){return P.has(t)}function $(t,e){let n=A().fields[t];if(void 0===n){if("birthtime"===t)return $.call(this,"ctime",e);const n=t.lastIndexOf("Ms");return n===t.length-2?$.call(this,t.substring(0,n),e).getTime():void 0}const[r,i]=n,o=("string"==typeof i?NativePointer.prototype["read"+i]:i).call(this.buffer.add(r),e);return o instanceof Int64||o instanceof UInt64?o.valueOf():o}function j(t){const e=this.readU32();let n=!1;0!=(1024&e)&&O(t,(t=>{const e=t.add(36).readU32();n=2684354563===e||2684354572===e}));const r=0!=(16&e);let i;return i=n?40960:r?16384:32768,i|=r?493:420,i}function q(){const t=BigInt(this.readU64().toString()).valueOf();return new Date(parseInt((t/10000n-11644473600000n).toString()))}function J(){const t=this.readU32(),e=this.add(4).readU32();return uint64(t).shl(32).or(e)}function Q(){const t=this.readU32(),e=this.add(4).readU32();return new Date(1e3*t+e/1e6)}function V(){const t=this.readU64().valueOf(),e=this.add(8).readU64().valueOf();return new Date(1e3*t+e/1e6)}function Z(){return 0}function tt(){return 1}function et(t){throw rt(t)}function nt(t){throw it(t)}function rt(t){const e=Memory.alloc(512);return u().FormatMessageW(4608,NULL,t,0,e,256,NULL),new Error(e.readUtf16String())}function it(t){const e=d().strerror(t).readUtf8String();return new Error(e)}function ot(t){return function(...e){const n=e.length-1,r=e.slice(0,n),i=e[n];a.nextTick((function(){try{const e=t(...r);i(null,e)}catch(t){i(t)}}))}}const lt=SystemFunction,st=NativeFunction,at=8===m?"int64":"int32",ct="u"+at,ut="darwin"===f||8===m?"int64":"int32";function dt(t,e,n){return t(3,e,n)}function ft(t){return t.reduce(((t,e)=>(function(t,e){const[n]=e;Object.defineProperty(t,n,{configurable:!0,get(){const[,r,i,o,l]=e;let s=null;const a=p?Module.findExportByName("kernel32.dll",n):Module.findExportByName(null,n);return null!==a&&(s=new r(a,i,o,mt)),void 0!==l&&(s=l.bind(null,s)),Object.defineProperty(t,n,{value:s}),s}})}(t,e),t)),{})}const mt=p&&4===m?{abi:"stdcall"}:{};export function createReadStream(t){return new h(t)}export function createWriteStream(t){return new _(t)}export const readdir=ot(C);export const readFile=ot(b);export const writeFile=ot(v);export const readlink=ot(E);export const rmdir=ot(W);export const unlink=ot(I);export const stat=ot(L);export const lstat=ot(M);function pt(t){let e,n=!1;return function(...r){return n||(e=t(...r),n=!0),e}}export{S as constants,C as readdirSync,T as list,b as readFileSync,v as writeFileSync,E as readlinkSync,W as rmdirSync,I as unlinkSync,L as statSync,M as lstatSync,B as Stats};export default{constants:S,createReadStream,createWriteStream,readdir,readdirSync:C,list:T,readFile,readFileSync:b,writeFile,writeFileSync:v,readlink,readlinkSync:E,rmdir,rmdirSync:W,unlink,unlinkSync:I,stat,statSync:L,lstat,lstatSync:M,Stats:B};
✄
{"version":3,"file":"index.js","names":["EventEmitter","Readable","Writable","Controller","constructor","this","events","sources","Map","nextEndpointId","requests","nextRequestId","onCreate","payload","endpoint","source","Source","set","id","emit","onFinish","get","undefined","Error","delete","push","onWrite","data","deliver","handlers","open","label","details","Sink","receive","packet","stanza","name","type","onRequest","onNotification","_request","Promise","resolve","reject","handler","result","e","then","value","catch","error","message","toString","request","response","super","onReadComplete","delivery","_read","size","chunk","length","tryComplete","controller","once","_onFinish","bind","_write","encoding","callback","_"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/frida-remote-stream/dist/","sources":[""],"mappings":"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
```