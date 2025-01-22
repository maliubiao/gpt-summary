Response:
The user wants to understand the functionality of the Frida script `fs_agent.js`. I need to analyze the code and identify its core capabilities related to file system operations. The request also asks for examples of how to replicate the functionality using LLDB, specifically focusing on interactions with the binary level, Linux kernel (if applicable), and potential user errors.

Here's a breakdown of the identified functionalities:

1. **Listing files and directories (ls):** The script can list the contents of directories, including details like permissions, size, modification time, and user/group ownership. It handles symbolic links and errors during listing.
2. **Removing files and directories (rm):** The script can remove files and directories, with options for recursive deletion and forced removal (ignoring errors). It also reports errors encountered during the removal process.
3. **Pulling files (pull):** The script can transfer files from the target device to the host where Frida is running. It provides progress updates and handles potential I/O errors during the transfer.
4. **Stream handling:** The script uses `RemoteStreamController` to manage data streams for file operations, likely for transferring file contents.
5. **User and Group ID resolution:** It attempts to resolve user and group IDs to names, using system functions like `getpwuid_r` and `getgrgid_r` on non-Windows platforms.

Now, let's formulate the response, addressing each point from the prompt:

- **功能列举:**  Summarize the core functionalities.
- **二进制底层/Linux内核举例:** Point out the usage of system functions like `getpwuid_r` and `getgrgid_r` and how they interact with the underlying operating system to get user and group information.
- **LLDB复刻:**  Since this is the *agent* side implementing the file system operations, directly replicating it with LLDB is difficult. The agent interacts with the *target* process. If the agent was *calling* some specific system call (e.g., `open`, `read`, `write`), we could set breakpoints in LLDB on those calls. However, here the agent *implements* the logic based on higher-level `frida-fs` module. Therefore, the LLDB example would be more about inspecting the *target process* when the agent is performing actions. For example, if the agent is listing a directory, we could set breakpoints on syscalls like `getdents64` or `readdir` in the target process.
- **逻辑推理 (假设输入与输出):** For the `ls` command, provide an example of an input path and the expected output format showing the file details. For `rm`, show an input path and the expectation that the file will be gone. For `pull`, show an input file path and the expectation that the file content will be transferred.
- **用户/编程常见错误:**  Highlight potential issues like incorrect file paths, permissions problems, or trying to remove non-empty directories without the recursive flag.
- **用户操作到达此处的步骤:** Describe a typical Frida workflow involving connecting to a target process and then using a Frida script that utilizes the `fs` module and the `fs_agent`.
- **功能归纳:** Provide a concise summary of the overall purpose of the script.好的，这是对提供的 Frida 脚本 `fs_agent.js` 功能的归纳，基于目录结构和部分代码片段：

**功能归纳:**

`fs_agent.js` 是一个 Frida 动态插桩工具的代理（agent）脚本，其主要功能是为 Frida 提供对目标进程文件系统的访问和操作能力。 它允许用户通过 Frida  API  在目标进程的上下文中执行文件系统相关的操作，例如：

1. **列出目录内容 (`ls`)**:  能够列出指定路径下的文件和子目录，并提供详细信息，例如文件类型、权限、链接数、用户 ID、组 ID、大小和修改时间。
2. **删除文件和目录 (`rm`)**: 能够删除指定的文件或目录，支持递归删除非空目录（需要指定 `force` 或 `recursive` 选项）。
3. **拉取文件 (`pull`)**: 能够将目标进程文件系统中的文件内容传输到 Frida 运行的主机上。

**详细功能说明:**

* **模块依赖:** 该脚本依赖于多个 Frida 提供的和 npm 安装的模块，这些模块共同构建了其文件系统操作能力：
    * `frida-remote-stream`:  用于处理远程数据流，可能用于文件内容的传输。
    * `fs`:  Node.js 的 `fs` 模块，尽管在 Frida agent 中运行，它可能被 Frida 桥接到目标进程的文件系统接口。
    * `path`: Node.js 的 `path` 模块，用于处理文件路径。
    * 其他 `@frida` 开头的模块 (如 `buffer`, `events`, `util` 等): 提供底层的数据处理、事件管理和实用工具函数。
    * `frida-fs`: 一个专门为 Frida 设计的文件系统操作模块，该 `fs_agent.js` 应该是其一部分。

* **`ls` 功能:**
    *  遍历指定的路径（可以是一个或多个）。
    *  使用 `lstatSync` 获取文件或目录的元数据信息（包括是否为符号链接）。
    *  如果是符号链接，则尝试使用 `statSync` 获取链接目标的元数据，并判断目标是否为目录。
    *  如果是目录，则使用 `readdirSync` 读取目录内容。
    *  对于每个文件或子目录，调用 `entryFromStats` 函数生成包含详细信息的条目。
    *  `entryFromStats` 函数根据文件模式 (`mode`) 判断文件类型 (`type`)，并调用 `permissionsFromMode` 生成权限字符串。
    *  如果是非 Windows 平台，会尝试使用 `getpwduidR` 和 `getgrgidR` 系统函数将用户 ID (`uid`) 和组 ID (`gid`) 解析为用户名和组名。
    *  处理遍历过程中遇到的错误，并将错误信息添加到结果中。

* **`rm` 功能:**
    *  支持递归删除 (`recursive` 选项): 如果指定了递归删除，则会先遍历目录及其子目录，将所有文件放入待删除的文件列表，将所有目录放入待删除的目录列表。
    *  删除文件：使用 `unlinkSync` 删除文件。
    *  删除目录：使用 `rmdirSync` 删除目录。
    *  强制删除 (`force` 选项): 如果指定了强制删除，则在删除文件或目录失败时会忽略错误。否则，会将错误信息收集起来。

* **`pull` 功能:**
    *  计算待拉取文件的总大小。
    *  为每个文件创建一个读取流 (`createReadStream`)。
    *  通过 `RemoteStreamController` 的 `open` 方法建立一个远程流，将文件内容传输到主机。
    *  使用 Promise 处理异步传输过程，监听读取流和远程流的 `error` 和 `finish` 事件。
    *  如果传输过程中发生错误，会发送带有错误信息的事件。

* **用户和组 ID 解析:**
    *  在非 Windows 平台上，`entryFromStats` 函数会尝试使用 `SystemFunction` 调用 `getpwuid_r` 和 `getgrgid_r` 这两个 glibc 提供的系统函数。
    *  `getpwuid_r` 根据用户 ID 获取用户信息结构体，从中提取用户名。
    *  `getgrgid_r` 根据组 ID 获取组信息结构体，从中提取组名。
    *  为了提高效率，用户名和组名会被缓存到 `cachedUsers` 和 `cachedGroups`  Map 中。
    *  如果系统调用失败（例如，找不到对应的用户或组），则会使用数字 ID 的字符串形式。

**涉及二进制底层/Linux内核的举例说明:**

* **`getpwduidR` 和 `getgrgidR` 系统函数:**  这两个函数是直接与 Linux 内核交互的 C 语言函数，用于获取用户和组的信息。Frida 通过 `SystemFunction` 允许 JavaScript 代码调用这些底层的二进制函数。
    * **举例:**  当 `ls` 命令需要显示文件所有者的用户名时，在 Linux 系统上，`fs_agent.js` 会调用 `getpwduidR`，传入文件的 `uid`。内核会查找对应的用户信息，并将结果返回给 Frida agent。
    * **LLDB 复刻思路:**  可以使用 LLDB 附加到目标进程，并在 `getpwduid_r` 和 `getgrgid_r` 函数入口处设置断点。当 Frida agent 执行 `ls` 命令时，如果涉及到用户或组 ID 解析，断点会被触发，你可以查看传入的参数（`uid` 或 `gid`）以及函数返回的结构体内容。
        ```lldb
        (lldb) attach -n <目标进程名或PID>
        (lldb) breakpoint set -n getpwuid_r
        (lldb) breakpoint set -n getgrgid_r
        (lldb) continue
        ```
        在 Frida agent 执行 `ls` 命令后，断点可能会被触发，此时可以使用 `frame variable` 命令查看局部变量。

**用 LLDB 指令或 LLDB Python 脚本复刻调试功能的示例:**

由于 `fs_agent.js` 是在目标进程中运行的 Frida agent，它直接操作目标进程的文件系统。使用 LLDB 完全复刻其功能比较困难，因为 LLDB 主要用于调试二进制代码。 不过，我们可以使用 LLDB 观察目标进程在执行文件系统操作时的状态。

**假设用户使用 Frida 连接到目标进程并执行了以下操作:**

```python
import frida

session = frida.attach("目标进程名或PID")
script = session.create_script("""
    const fs = require('frida-fs');
    console.log(fs.ls("/tmp"));
""")
script.load()
```

**LLDB 复刻示例 (观察目标进程执行 `ls /tmp`):**

1. **附加到目标进程:**
   ```lldb
   (lldb) attach -n <目标进程名或PID>
   ```

2. **在相关的系统调用处设置断点:**  `fs.ls` 内部可能会调用多个系统调用，例如 `open`, `read`, `close`, `getdents64` (用于读取目录项)。我们可以选择其中一个或多个进行观察。这里以 `getdents64` 为例（Linux 系统）。
   ```lldb
   (lldb) breakpoint set -n getdents64
   ```

3. **继续执行目标进程:**
   ```lldb
   (lldb) continue
   ```

4. **当断点触发时，查看寄存器和内存:**  当 Frida agent 执行到读取 `/tmp` 目录的操作时，`getdents64` 断点会被触发。可以查看寄存器和内存来了解传递给 `getdents64` 的参数以及返回结果。
   ```lldb
   (lldb) register read  // 查看寄存器
   (lldb) memory read -s 256 -x $rdi  // 假设第一个参数（目录文件描述符）在 rdi 寄存器中
   (lldb) memory read -s 256 -x $rsi  // 假设第二个参数（dirent 结构体缓冲区）在 rsi 寄存器中
   (lldb) continue
   ```

**LLDB Python 脚本示例 (监控目标进程的文件系统相关系统调用):**

```python
import lldb

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('breakpoint set -n open')
    debugger.HandleCommand('breakpoint set -n read')
    debugger.HandleCommand('breakpoint set -n write')
    debugger.HandleCommand('breakpoint set -n close')
    debugger.HandleCommand('breakpoint set -n getdents64')

    def breakpoint_callback(frame, bp_loc, dict):
        thread = frame.GetThread()
        process = thread.GetProcess()
        thread_id = thread.GetThreadID()
        function_name = bp_loc.GetBreakpoint().GetLocationAtIndex(bp_loc.GetLocationID()).GetAddress().GetSymbol().GetName()
        print(f"Thread {thread_id} hit breakpoint at {function_name}")
        return lldb.eReturnSuccessFinishNoResult

    for bp in debugger.GetSelectedTarget().FindBreakpoints():
        bp.SetScriptCallbackFunction('file_monitor.breakpoint_callback')

```

将以上 Python 代码保存为 `file_monitor.py`，然后在 LLDB 中加载并附加到目标进程：

```lldb
(lldb) command script import file_monitor.py
(lldb) attach -n <目标进程名或PID>
(lldb) continue
```

当 Frida agent 执行文件系统操作时，脚本会打印出被调用的系统调用。

**逻辑推理 (假设输入与输出):**

**`ls` 命令:**

* **假设输入:**  Frida 执行 `fs.ls("/tmp")`
* **预期输出 (示例):**
  ```json
  [
    [
      "/tmp/example.txt",
      null,
      "-",
      "rw-r--r--",
      1,
      "user1",
      "group1",
      1024,
      1678886400000
    ],
    [
      "/tmp/example_dir",
      null,
      "d",
      "rwxr-xr-x",
      2,
      "user2",
      "group2",
      4096,
      1678886460000
    ]
  ]
  ```
  这个输出表示 `/tmp` 目录下有一个名为 `example.txt` 的文件和一个名为 `example_dir` 的目录，并列出了它们的详细信息。

**`rm` 命令:**

* **假设输入:** Frida 执行 `fs.rm("/tmp/example.txt")`
* **预期输出:**  执行成功后，`/tmp/example.txt` 文件将不再存在于目标进程的文件系统中。

**`pull` 命令:**

* **假设输入:** Frida 执行 `fs.pull("/tmp/important.data")`
* **预期输出:**  `important.data` 文件的内容将被传输到 Frida 运行的主机上，通常会保存在一个临时文件中或者可以通过 Frida API 获取其内容。

**用户或编程常见的使用错误举例说明:**

1. **路径错误:**
   * **错误操作:**  Frida 执行 `fs.ls("/non_existent_path")`
   * **结果:**  `ls` 命令会返回一个包含错误信息的结构，指示路径不存在。

2. **权限不足:**
   * **错误操作:**  用户尝试删除一个只读文件，且没有指定 `force` 选项。
   * **结果:**  `rm` 命令会返回一个错误，指示没有权限执行删除操作。

3. **尝试删除非空目录 (未指定递归):**
   * **错误操作:**  Frida 执行 `fs.rm("/tmp/non_empty_dir")`，但 `/tmp/non_empty_dir` 目录下有文件或子目录。
   * **结果:**  `rm` 命令会返回一个错误，指示目录非空，无法删除。需要使用 `fs.rm("/tmp/non_empty_dir", { recursive: true })`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:**  用户编写一个 Frida 脚本，该脚本导入了 `frida-fs` 模块，并使用了 `fs.ls`, `fs.rm` 或 `fs.pull` 等方法来操作目标进程的文件系统。

2. **用户使用 Frida 连接到目标进程:**  用户使用 Frida CLI 工具 (如 `frida`, `frida-ps`, `frida-trace`) 或 Python API 连接到目标应用程序进程。

3. **用户加载并执行 Frida 脚本:**  用户将编写的 Frida 脚本加载到目标进程中执行。Frida 会将 JavaScript 代码注入到目标进程的内存空间中并运行。

4. **`fs_agent.js` 在目标进程中运行:**  `frida-fs` 模块在目标进程中运行，并依赖于 `fs_agent.js` 来实现具体的文件系统操作。当用户在 Frida 脚本中调用 `fs.ls` 等方法时，这些调用会被路由到 `fs_agent.js` 中的相应函数。

5. **`fs_agent.js` 执行文件系统操作:**  `fs_agent.js` 利用其依赖的模块和系统调用接口，在目标进程的上下文中执行实际的文件系统操作，例如读取目录、删除文件等。

**总结:**  `fs_agent.js` 作为 `frida-fs` 模块的核心组成部分，为 Frida 提供了在目标进程中进行文件系统操作的能力，这对于安全分析、逆向工程和动态调试等场景非常有用。它通过 JavaScript 封装了底层的系统调用和文件系统 API，使得用户可以通过 Frida 方便地与目标进程的文件系统进行交互。

Prompt: 
```
这是目录为frida/build/subprojects/frida-tools/agents/fs/fs_agent.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共12部分，请归纳一下它的功能

"""
📦
8195 /agent.js.map
5134 /agent.js
2821 /node_modules/@frida/base64-js/index.js.map
1428 /node_modules/@frida/base64-js/index.js
↻ base64-js
36828 /node_modules/@frida/buffer/index.js.map
25206 /node_modules/@frida/buffer/index.js
↻ buffer
8085 /node_modules/@frida/events/events.js.map
5739 /node_modules/@frida/events/events.js
↻ events
2138 /node_modules/@frida/ieee754/index.js.map
1001 /node_modules/@frida/ieee754/index.js
↻ ieee754
17127 /node_modules/@frida/path/index.js.map
9533 /node_modules/@frida/path/index.js
↻ path
1295 /node_modules/@frida/process/index.js.map
1074 /node_modules/@frida/process/index.js
↻ process
2351 /node_modules/@frida/readable-stream/errors.js.map
2217 /node_modules/@frida/readable-stream/errors.js
2307 /node_modules/@frida/readable-stream/lib/abort_controller.js.map
1595 /node_modules/@frida/readable-stream/lib/abort_controller.js
983 /node_modules/@frida/readable-stream/lib/add-abort-signal.js.map
609 /node_modules/@frida/readable-stream/lib/add-abort-signal.js
3003 /node_modules/@frida/readable-stream/lib/buffer_list.js.map
1736 /node_modules/@frida/readable-stream/lib/buffer_list.js
2814 /node_modules/@frida/readable-stream/lib/compose.js.map
1771 /node_modules/@frida/readable-stream/lib/compose.js
4920 /node_modules/@frida/readable-stream/lib/destroy.js.map
3161 /node_modules/@frida/readable-stream/lib/destroy.js
6535 /node_modules/@frida/readable-stream/lib/duplex.js.map
4977 /node_modules/@frida/readable-stream/lib/duplex.js
3508 /node_modules/@frida/readable-stream/lib/end-of-stream.js.map
2065 /node_modules/@frida/readable-stream/lib/end-of-stream.js
14323 /node_modules/@frida/readable-stream/lib/event_target.js.map
10300 /node_modules/@frida/readable-stream/lib/event_target.js
1812 /node_modules/@frida/readable-stream/lib/from.js.map
1086 /node_modules/@frida/readable-stream/lib/from.js
1928 /node_modules/@frida/readable-stream/lib/legacy.js.map
1189 /node_modules/@frida/readable-stream/lib/legacy.js
358 /node_modules/@frida/readable-stream/lib/once.js.map
95 /node_modules/@frida/readable-stream/lib/once.js
554 /node_modules/@frida/readable-stream/lib/passthrough.js.map
238 /node_modules/@frida/readable-stream/lib/passthrough.js
4524 /node_modules/@frida/readable-stream/lib/pipeline.js.map
2667 /node_modules/@frida/readable-stream/lib/pipeline.js
794 /node_modules/@frida/readable-stream/lib/promises.js.map
409 /node_modules/@frida/readable-stream/lib/promises.js
18126 /node_modules/@frida/readable-stream/lib/readable.js.map
13334 /node_modules/@frida/readable-stream/lib/readable.js
832 /node_modules/@frida/readable-stream/lib/state.js.map
426 /node_modules/@frida/readable-stream/lib/state.js
2614 /node_modules/@frida/readable-stream/lib/transform.js.map
1644 /node_modules/@frida/readable-stream/lib/transform.js
3928 /node_modules/@frida/readable-stream/lib/utils.js.map
3422 /node_modules/@frida/readable-stream/lib/utils.js
12739 /node_modules/@frida/readable-stream/lib/writable.js.map
9107 /node_modules/@frida/readable-stream/lib/writable.js
1321 /node_modules/@frida/readable-stream/readable.js.map
1243 /node_modules/@frida/readable-stream/readable.js
↻ readable-stream
509 /node_modules/@frida/stream/index.js.map
438 /node_modules/@frida/stream/index.js
↻ stream
5129 /node_modules/@frida/string_decoder/lib/string_decoder.js.map
3481 /node_modules/@frida/string_decoder/lib/string_decoder.js
↻ string_decoder
3841 /node_modules/@frida/util/support/types.js.map
3002 /node_modules/@frida/util/support/types.js
12020 /node_modules/@frida/util/util.js.map
8557 /node_modules/@frida/util/util.js
↻ util
21881 /node_modules/frida-fs/dist/index.js.map
14522 /node_modules/frida-fs/dist/index.js
↻ fs
4246 /node_modules/frida-remote-stream/dist/index.js.map
3010 /node_modules/frida-remote-stream/dist/index.js
↻ frida-remote-stream
✄
{"version":3,"file":"agent.js","names":["Buffer","RemoteStreamController","fs","fsPath","S_IFMT","S_IFREG","S_IFDIR","S_IFCHR","S_IFBLK","S_IFIFO","S_IFLNK","S_IFSOCK","constants","pointerSize","Process","cachedUsers","Map","cachedGroups","getpwduidR","getgrgidR","entryFromStats","path","name","stats","mode","type","typeFromMode","target","targetPath","readlinkSync","targetType","targetPerms","s","statSync","permissionsFromMode","e","nlink","resolveUserID","uid","resolveGroupID","gid","size","mtimeMs","Error","toString","access","i","get","undefined","platform","pwd","SystemFunction","Module","getExportByName","buf","res","pwdCapacity","bufCapacity","Memory","alloc","add","r","value","errno","entry","readPointer","isNull","readUtf8String","set","group","groupCapacity","agent","constructor","_Agent_streamController","this","_Agent_onMessage","message","rawData","data","from","__classPrivateFieldGet","receive","stanza","payload","recv","_Agent_onStreamControllerSendRequest","packet","send","buffer","_Agent_onStreamControllerStreamRequest","stream","index","parseInt","label","details","filename","isDirectory","join","writer","createWriteStream","onStreamError","error","detachListeners","end","onWriterError","destroy","onWriterFinish","removeListener","pipe","addListener","events","on","ls","paths","length","fileGroup","entries","errors","directoryGroups","digDeeper","lstatSync","push","isSymbolicLink","names","readdirSync","curPath","rm","flags","dirs","files","force","includes","pending","slice","shift","filter","map","unshift","unlinkSync","collectError","rmdirSync","async","total","reader","createReadStream","open","transfer","Promise","resolve","reject","onReaderError","rpc","exports","bind","pull"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/","sources":["agent.ts"],"mappings":"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"}
✄
var e,t,r,n,s=this&&this.__classPrivateFieldGet||function(e,t,r,n){if("a"===r&&!n)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!n:!t.has(e))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===r?n:"a"===r?n.call(e):n?n.value:t.get(e)};import{Buffer as o}from"buffer";import i from"frida-remote-stream";import a from"fs";import c from"path";const{S_IFMT:l,S_IFREG:u,S_IFDIR:f,S_IFCHR:d,S_IFBLK:p,S_IFIFO:h,S_IFLNK:m,S_IFSOCK:y}=a.constants,{pointerSize:S}=Process,w=new Map,g=new Map;let v=null,b=null;function L(e,t,r){const{mode:n}=r,s=I(n);let o;if("l"===s){const t=a.readlinkSync(e);let r,n;try{const t=a.statSync(e);n=_(t.mode),r=I(t.mode)}catch(e){r=null}o=[t,null!==r?[r,n]:null]}else o=null;return[t,o,s,_(n),r.nlink,F(r.uid),M(r.gid),r.size,r.mtimeMs]}function I(e){switch(e&l){case u:return"-";case f:return"d";case d:return"c";case p:return"b";case h:return"p";case m:return"l";case y:return"s"}throw new Error(`Invalid mode: 0x${e.toString(16)}`)}function _(e){let t="";for(let r=8;-1!==r;r-=3)t+=0!=(e>>>r&1)?"r":"-",t+=0!=(e>>>r-1&1)?"w":"-",t+=0!=(e>>>r-2&1)?"x":"-";return t}function F(e){let t=w.get(e);if(void 0!==t)return t;if("windows"===Process.platform)t=e.toString();else{let r;null===v&&(v=new SystemFunction(Module.getExportByName(null,"getpwuid_r"),"int",["uint","pointer","pointer","size_t","pointer"]));let n,s,o=128,i=1024;for(;;){r=Memory.alloc(o+i+S),n=r.add(o),s=n.add(i);const t=v(e,r,n,i,s);if(0===t.value)break;if(34!==t.errno)throw new Error(`Unable to resolve user ID ${e}: ${t.errno}`);i*=2}const a=s.readPointer();t=a.isNull()?e.toString():a.readPointer().readUtf8String()}return w.set(e,t),t}function M(e){let t=g.get(e);if(void 0!==t)return t;if("windows"===Process.platform)t=e.toString();else{let r;null===b&&(b=new SystemFunction(Module.getExportByName(null,"getgrgid_r"),"int",["uint","pointer","pointer","size_t","pointer"]));let n,s,o=128,i=1024;for(;;){r=Memory.alloc(o+i+S),n=r.add(o),s=n.add(i);const t=b(e,r,n,i,s);if(0===t.value)break;if(34!==t.errno)throw new Error(`Unable to resolve group ID ${e}: ${t.errno}`);i*=2}const a=s.readPointer();t=a.isNull()?e.toString():a.readPointer().readUtf8String()}return g.set(e,t),t}e=new WeakMap,t=new WeakMap,r=new WeakMap,n=new WeakMap;const k=new class{constructor(){e.set(this,new i),t.set(this,((r,n)=>{if("stream"===r.type){const t=null!==n?o.from(n):null;s(this,e,"f").receive({stanza:r.payload,data:t})}recv(s(this,t,"f"))})),r.set(this,(e=>{send({type:"stream",payload:e.stanza},e.data?.buffer)})),n.set(this,(e=>{const t=parseInt(e.label),r=e.details,n=r.filename,s=r.target;let o=null;try{a.statSync(s).isDirectory()&&(o=c.join(s,n))}catch(e){}null===o&&(o=s);const i=a.createWriteStream(o);function l(e){d(),i.end(),send({type:"push:io-error",index:t,error:e.message})}function u(r){d(),e.destroy(),send({type:"push:io-error",index:t,error:r.message})}function f(){d(),send({type:"push:io-success",index:t})}function d(){i.removeListener("finish",f),i.removeListener("error",u),e.removeListener("error",l)}e.pipe(i),e.addListener("error",l),i.addListener("error",u),i.addListener("finish",f)})),recv(s(this,t,"f")),s(this,e,"f").events.on("send",s(this,r,"f")),s(this,e,"f").events.on("stream",s(this,n,"f"))}ls(e){0===e.length&&(e=["windows"===Process.platform?"C:\\":"/"]);const t={path:"",entries:[],errors:[]},r=[];for(const n of e){let e,s;try{e=a.lstatSync(n)}catch(e){t.errors.push([n,e.message]);continue}if(e.isSymbolicLink()){let t;try{t=a.statSync(n),s=t.isDirectory(),s&&(e=t)}catch(e){s=!1}}else s=e.isDirectory();if(s){let t;try{t=a.readdirSync(n)}catch(e){r.push({path:n,entries:[],errors:[[n,e.message]]});continue}const s=[];for(const r of t){const t=c.join(n,r);try{const n=L(t,r,"."===r?e:a.lstatSync(t));s.push(n)}catch(e){}}r.push({path:n,entries:s,errors:[]})}else t.entries.push(L(n,n,e))}return t.entries.length>0||t.errors.length>0?[t,...r]:r}rm(e,t){const r=[],n=[],s=[],o=t.includes("force");if(t.includes("recursive")){const t=e.slice();for(;;){const e=t.shift();if(void 0===e)break;let r;try{r=a.statSync(e)}catch(t){s.push(e);continue}r.isDirectory()?(t.push(...a.readdirSync(e).filter((e=>"."!==e&&".."!==e)).map((t=>c.join(e,t)))),n.unshift(e)):s.unshift(e)}}else s.push(...e);for(const e of s)try{a.unlinkSync(e)}catch(t){o||i(e,t)}for(const e of n)try{a.rmdirSync(e)}catch(t){i(e,t)}function i(e,t){r.push(`${e}: ${t.message}`)}return r}async pull(t){let r=0;for(const e of t)try{r+=a.statSync(e).size}catch(e){}send({type:"pull:status",total:r});let n=0;for(const r of t){const t=a.createReadStream(r),o=t.pipe(s(this,e,"f").open(n.toString())),i=new Promise(((e,r)=>{function n(e){a(),o.end(),r(e)}function s(r){a(),t.destroy(),e(null)}function i(){a(),e(null)}function a(){o.removeListener("finish",i),o.removeListener("error",s),t.removeListener("error",n)}t.addListener("error",n),o.addListener("error",s),o.addListener("finish",i)}));try{await i}catch(e){send({type:"pull:io-error",index:n,error:e.message})}n++}}};rpc.exports={ls:k.ls.bind(k),rm:k.rm.bind(k),pull:k.pull.bind(k)};
✄
{"version":3,"file":"index.js","names":["lookup","revLookup","code","i","len","length","charCodeAt","getLens","b64","Error","validLen","indexOf","byteLength","lens","placeHoldersLen","toByteArray","arr","Uint8Array","_byteLength","curByte","tmp","encodeChunk","uint8","start","end","output","push","num","join","fromByteArray","extraBytes","parts","maxChunkLength","len2"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/base64-js/","sources":[""],"mappings":"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"}
✄
const t=[],o=[],n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";for(let c=0,h=n.length;c<h;++c)t[c]=n[c],o[n.charCodeAt(c)]=c;function r(t){const o=t.length;if(o%4>0)throw new Error("Invalid string. Length must be a multiple of 4");let n=t.indexOf("=");-1===n&&(n=o);return[n,n===o?0:4-n%4]}o["-".charCodeAt(0)]=62,o["_".charCodeAt(0)]=63;export function byteLength(t){const o=r(t),n=o[0],e=o[1];return 3*(n+e)/4-e}export function toByteArray(t){const n=r(t),e=n[0],c=n[1],h=new Uint8Array(function(t,o,n){return 3*(o+n)/4-n}(0,e,c));let s=0;const a=c>0?e-4:e;let f;for(f=0;f<a;f+=4){const n=o[t.charCodeAt(f)]<<18|o[t.charCodeAt(f+1)]<<12|o[t.charCodeAt(f+2)]<<6|o[t.charCodeAt(f+3)];h[s++]=n>>16&255,h[s++]=n>>8&255,h[s++]=255&n}if(2===c){const n=o[t.charCodeAt(f)]<<2|o[t.charCodeAt(f+1)]>>4;h[s++]=255&n}if(1===c){const n=o[t.charCodeAt(f)]<<10|o[t.charCodeAt(f+1)]<<4|o[t.charCodeAt(f+2)]>>2;h[s++]=n>>8&255,h[s++]=255&n}return h}function e(o,n,r){const e=[];for(let h=n;h<r;h+=3){const n=(o[h]<<16&16711680)+(o[h+1]<<8&65280)+(255&o[h+2]);e.push(t[(c=n)>>18&63]+t[c>>12&63]+t[c>>6&63]+t[63&c])}var c;return e.join("")}export function fromByteArray(o){const n=o.length,r=n%3,c=[],h=16383;for(let t=0,s=n-r;t<s;t+=h)c.push(e(o,t,t+h>s?s:t+h));if(1===r){const r=o[n-1];c.push(t[r>>2]+t[r<<4&63]+"==")}else if(2===r){const r=(o[n-2]<<8)+o[n-1];c.push(t[r>>10]+t[r>>4&63]+t[r<<2&63]+"=")}return c.join("")}
✄
{"version":3,"file":"index.js","names":["base64","ieee754","config","INSPECT_MAX_BYTES","K_MAX_LENGTH","createBuffer","length","RangeError","buf","Uint8Array","Object","setPrototypeOf","Buffer","prototype","TYPED_ARRAY_SUPPORT","defineProperty","enumerable","get","isBuffer","this","buffer","byteOffset","arg","encodingOrOffset","TypeError","allocUnsafe","from","value","string","encoding","isEncoding","byteLength","actual","write","slice","fromString","ArrayBuffer","isView","arrayView","copy","fromArrayBuffer","fromArrayLike","fromArrayView","SharedArrayBuffer","valueOf","b","obj","len","checked","undefined","Number","isNaN","type","Array","isArray","data","fromObject","Symbol","toPrimitive","assertSize","size","array","i","toString","poolSize","alloc","fill","allocUnsafeSlow","SlowBuffer","mustMatch","arguments","loweredCase","utf8ToBytes","base64ToBytes","toLowerCase","slowToString","start","end","hexSlice","utf8Slice","asciiSlice","latin1Slice","base64Slice","utf16leSlice","swap","n","m","bidirectionalIndexOf","val","dir","arrayIndexOf","indexOf","call","lastIndexOf","arr","indexSize","arrLength","valLength","String","read","readUInt16BE","foundIndex","found","j","hexWrite","offset","remaining","strLen","parsed","parseInt","substr","utf8Write","blitBuffer","asciiWrite","str","byteArray","push","charCodeAt","asciiToBytes","base64Write","ucs2Write","units","c","hi","lo","utf16leToBytes","fromByteArray","Math","min","res","firstByte","codePoint","bytesPerSequence","secondByte","thirdByte","fourthByte","tempCodePoint","codePoints","fromCharCode","apply","decodeCodePointsArray","_isBuffer","compare","a","x","y","concat","list","pos","set","swap16","swap32","swap64","toLocaleString","equals","inspect","max","replace","trim","for","target","thisStart","thisEnd","thisCopy","targetCopy","includes","isFinite","Error","toJSON","_arr","ret","out","hexSliceLookupTable","bytes","checkOffset","ext","checkInt","wrtBigUInt64LE","checkIntBI","BigInt","wrtBigUInt64BE","checkIEEE754","writeFloat","littleEndian","noAssert","writeDouble","newBuf","subarray","readUintLE","readUIntLE","mul","readUintBE","readUIntBE","readUint8","readUInt8","readUint16LE","readUInt16LE","readUint16BE","readUint32LE","readUInt32LE","readUint32BE","readUInt32BE","readBigUInt64LE","validateNumber","first","last","boundsError","readBigUInt64BE","readIntLE","pow","readIntBE","readInt8","readInt16LE","readInt16BE","readInt32LE","readInt32BE","readBigInt64LE","readBigInt64BE","readFloatLE","readFloatBE","readDoubleLE","readDoubleBE","writeUintLE","writeUIntLE","writeUintBE","writeUIntBE","writeUint8","writeUInt8","writeUint16LE","writeUInt16LE","writeUint16BE","writeUInt16BE","writeUint32LE","writeUInt32LE","writeUint32BE","writeUInt32BE","writeBigUInt64LE","writeBigUInt64BE","writeIntLE","limit","sub","writeIntBE","writeInt8","writeInt16LE","writeInt16BE","writeInt32LE","writeInt32BE","writeBigInt64LE","writeBigInt64BE","writeFloatLE","writeFloatBE","writeDoubleLE","writeDoubleBE","targetStart","copyWithin","code","errors","E","sym","getMessage","Base","constructor","super","writable","configurable","name","stack","message","addNumericalSeparator","range","ERR_OUT_OF_RANGE","checkBounds","ERR_INVALID_ARG_TYPE","floor","ERR_BUFFER_OUT_OF_BOUNDS","input","msg","received","isInteger","abs","INVALID_BASE64_RE","Infinity","leadSurrogate","toByteArray","split","base64clean","src","dst","alphabet","table","i16","kMaxLength"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/buffer/","sources":[""],"mappings":"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
"""


```