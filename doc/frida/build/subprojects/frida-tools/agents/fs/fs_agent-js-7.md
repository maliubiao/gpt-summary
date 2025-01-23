Response:
Let's break down the thought process to analyze the `fs_agent.js` code and generate the comprehensive response.

**1. Initial Understanding and Goal Identification:**

The core request is to analyze the provided JavaScript code for a Frida agent related to the file system (`fs`). The key requirements are to:

*   List its functionalities.
*   Explain any interaction with the binary level, Linux kernel (with examples).
*   Provide examples of replicating its debugging capabilities with LLDB (or Python scripts if it *is* a debugging tool).
*   Offer logical inference with input/output examples.
*   Highlight common user/programming errors.
*   Describe the user journey to reach this code.
*   Summarize its overall function (as part 8 of 12).

**2. High-Level Code Structure Recognition:**

Quickly scanning the code reveals standard JavaScript patterns for creating readable streams using Node.js's `stream` module. Keywords like `Readable`, `Transform`, `Duplex`, `push`, `pipe`, and event listeners (`data`, `end`, `error`, `close`) are strong indicators. The presence of `require` or `import` statements also points to modularity.

**3. Deeper Dive and Functional Decomposition (Iterative Process):**

I started reading the code more carefully, focusing on the class definitions (`Readable`, `Transform`).

*   **`Readable` Class:**  This immediately suggests the agent *reads* data, likely representing file system events or data. Key methods like `push`, `read`, `pipe`, and event handlers confirm this. The internal state management (`_readableState`) is also a crucial element of Node.js streams.

*   **`Transform` Class:** This implies data manipulation or transformation as it flows through the agent. The `_transform` method (which throws an error, suggesting it needs to be implemented) is the central point.

*   **Key Imports:**  Noting the imports is critical:
    *   `addAbortSignal`:  Indicates handling of cancellation.
    *   `buffer_list`: Suggests efficient buffer management.
    *   `destroy`:  For proper resource cleanup.
    *   `end-of-stream`:  Handling stream completion.
    *   `../errors.js`: Custom error definitions.
    *   `./from.js`: Creating readable streams from other sources.
    *   `./legacy.js`: Compatibility with older stream implementations.
    *   `./state.js`: Managing the internal state of the streams.
    *   `buffer`, `events`, `process`, `string_decoder`: Core Node.js modules.

*   **Identifying Core Actions:** I started listing the distinct actions the code defines:
    *   Creating readable streams.
    *   Transforming data.
    *   Handling stream events (data, end, error, close, readable, finish, drain, pipe, unpipe, pause, resume).
    *   Managing internal state (buffering, flowing, ending).
    *   Error handling.
    *   Support for different encoding types.

**4. Inferring Functionality Based on Naming and Patterns:**

Even without fully understanding every line, names like `getDefaultHighWaterMark`, `getHighWaterMark`, `isPaused`, `setEncoding`, `destroy`, `push`, `unshift`, `pipe`, `unpipe`, `resume`, and `pause` strongly suggest the standard operations of readable streams. The `Transform` class suggests interception and modification of data.

**5. Connecting to Binary/Kernel/OS (Hypothesis and Verification):**

The name "fs_agent" is the primary clue here. "fs" strongly suggests file system interaction. However, *this particular code snippet doesn't directly show any system calls or binary manipulation.*  It focuses on the stream processing aspect.

Therefore, my reasoning went like this:

*   **Hypothesis:** The agent *must* interact with the OS to get file system data, but this specific file is about *how the data is processed once received*.
*   **Verification:** I scanned the code for direct calls to OS-level APIs (like `open`, `read`, `write` in the `fs` module). They are *not present* in this snippet.
*   **Conclusion:**  The interaction with the kernel and binary level likely happens *elsewhere* (in the Frida instrumentation code that *uses* this agent). This agent *processes* the data that the instrumentation layer provides. This distinction is crucial.

**6. LLDB/Debugging Replication:**

Since the code *itself* primarily implements stream processing logic and *not* the direct file system monitoring, directly replicating it with LLDB isn't feasible. LLDB operates at a lower level.

My thought process:

*   **Analyze the Code's Purpose:** It handles data flow, transformations, and events.
*   **Consider LLDB's Capabilities:** LLDB excels at inspecting program state, breakpoints, and stepping through code.
*   **Conclusion:**  LLDB could be used to debug the *Frida instrumentation layer* that feeds data to this agent. You could set breakpoints in the instrumentation code to observe the data *before* it enters the agent. You could also inspect the agent's internal state after it receives data. This led to the examples focusing on inspecting variables and setting breakpoints within the context of a Frida environment.

**7. Logical Inference and Input/Output:**

To demonstrate the agent's behavior, I needed hypothetical scenarios.

*   **Scenario:** Imagine monitoring file reads.
*   **Input:**  The instrumentation layer detects a `read()` system call on a specific file.
*   **Agent's Action:** The agent receives the file content as a stream of data chunks.
*   **Transformation (if `Transform` were implemented):** The agent might filter, modify, or analyze the content.
*   **Output:** The agent emits `data` events with the (potentially transformed) content.

**8. Common Errors:**

Thinking about how users might interact with or misuse streams led to examples like:

*   Not handling `error` events.
*   Forgetting to `pipe` streams correctly.
*   Incorrectly implementing `_transform`.
*   Backpressure issues (not handling `drain` events).

**9. User Journey:**

This required thinking about how someone would end up looking at this specific file:

*   Starting with Frida and file system monitoring.
*   Exploring Frida's agent structure.
*   Navigating the file system within the Frida agent's code.
*   Arriving at `frida/build/subprojects/frida-tools/agents/fs/fs_agent.js`.

**10. Summarization:**

The key is to concisely capture the main function: processing file system data as a stream within the Frida framework. Highlighting its role as an intermediary that receives data from instrumentation and potentially transforms it before passing it on.

**11. Review and Refinement:**

Finally, I reviewed the entire response to ensure accuracy, clarity, and completeness, checking that all parts of the prompt were addressed. I made sure the language was understandable and the examples were helpful. For example, initially, I might have focused too much on the theoretical possibility of direct OS interaction within this file. Reviewing helped me clarify that the interaction likely occurs at a different layer.这是一个名为 `fs_agent.js` 的 Frida 动态Instrumentation工具的源代码文件，它位于 `frida/build/subprojects/frida-tools/agents/fs/` 目录下。从代码结构和导入的模块来看，它的主要功能是**作为一个可读流 (`Readable`) 或可转换流 (`Transform`) 来处理文件系统相关的事件或数据**。

以下是其功能的详细分解：

**1. 作为可读流 (`Readable`) 提供数据:**

*   **核心功能:**  代码中定义了 `Readable` 类，这意味着这个 agent 可以作为数据源，向其他部分（例如，发送到 Frida 客户端）提供数据。
*   **数据来源推测:**  由于命名为 `fs_agent`，其数据来源很可能是通过 Frida 拦截到的文件系统相关的系统调用或事件。例如，文件的读取、写入、创建、删除、目录的遍历等。
*   **数据格式:**  具体的数据格式需要查看更上层的 Frida instrumentation 代码如何将底层事件转化为 JavaScript 对象或数据结构。
*   **背压控制:**  `Readable` 类实现了背压控制机制（通过 `highWaterMark` 等属性），防止数据产生速度过快导致内存溢出。

**2. 作为可转换流 (`Transform`) 处理数据:**

*   **核心功能:** 代码中也定义了 `Transform` 类，这表明该 agent 可以接收来自其他流的数据，并对其进行转换或处理后再输出。
*   **数据转换推测:** 结合 `fs_agent` 的命名，可能的转换操作包括：
    *   **过滤:**  只传递特定类型的文件系统事件或针对特定路径的操作。
    *   **格式化:** 将原始的事件数据转换成更易于阅读或分析的格式。
    *   **聚合:**  将多个相关的事件组合成一个更有意义的数据单元。
    *   **增强:**  添加额外的信息，例如进程 ID、时间戳等。
*   **`_transform` 方法:**  `Transform` 类中的 `_transform` 方法是实际执行转换逻辑的地方。但在此代码片段中，`_transform` 只是抛出一个错误，说明具体的转换逻辑需要在其他地方实现或被子类化。

**3. 涉及到的二进制底层和 Linux 内核 (推测):**

虽然这段 JavaScript 代码本身没有直接操作二进制或进行系统调用，但它作为 Frida agent，其背后的机制必然涉及到与底层交互：

*   **Frida 的 Instrumentation 机制:** Frida 通过在目标进程的内存空间中注入 JavaScript 代码，并 hook (拦截)  目标进程的函数调用来实现动态 instrumentation。对于文件系统监控，Frida 需要 hook 与文件操作相关的系统调用，例如：
    *   **`open()`:**  打开文件。可以获取文件名、打开模式等信息。
    *   **`read()`:** 读取文件内容。可以获取读取的字节数和数据。
    *   **`write()`:** 写入文件内容。可以获取写入的字节数和数据。
    *   **`close()`:** 关闭文件。
    *   **`unlink()`:** 删除文件。
    *   **`mkdir()`/`rmdir()`:** 创建/删除目录。
    *   **`readdir()`:** 读取目录内容。
    *   **`stat()`/`lstat()`:** 获取文件/目录的元数据（大小、权限、时间戳等）。
*   **数据传递:** Frida 的 C++ 代码会将这些 hook 到的系统调用参数和返回值传递给 JavaScript agent。这可能涉及到将二进制数据（例如，文件内容）转换为 JavaScript 可以处理的类型 (例如，`Buffer` 对象)。
*   **Linux 内核:**  以上列举的都是 Linux 系统调用。Frida 的 instrumentation 代码需要理解 Linux 内核提供的这些接口，才能正确地进行 hook 和数据提取。

**举例说明:**

假设 Frida instrumentation 代码 hook 了 `open()` 系统调用。

1. 当目标进程调用 `open("/tmp/test.txt", O_RDONLY)` 时，Frida 的 C++ 代码会拦截这次调用。
2. Frida C++ 代码会提取 `open()` 的参数，例如文件名 `/tmp/test.txt` 和打开模式 `O_RDONLY`。
3. 这些信息会被转换为 JavaScript 可以理解的数据结构，例如一个包含 `filename: "/tmp/test.txt"` 和 `flags: "O_RDONLY"` 的对象。
4. 这个 JavaScript 对象会被传递到 `fs_agent.js` 创建的 `Readable` 或 `Transform` 流中，作为数据的一部分。
5. `fs_agent.js` 可能会将这个对象进一步处理或直接通过 `data` 事件发送到 Frida 客户端。

**4. 用 LLDB 指令或 LLDB Python 脚本复刻调试功能的示例 (假设源代码是调试功能的实现):**

由于 `fs_agent.js` 本身是 *实现* 监控功能的代码，而不是 *调试* 代码，直接用 LLDB 复刻它的功能是不可能的。LLDB 是一个底层调试器，用于调试 C/C++ 代码或汇编代码。

但是，我们可以用 LLDB 来调试 *Frida 的 C++ 代码*，从而理解 Frida 是如何实现文件系统 hook 并将数据传递给 JavaScript agent 的。

**LLDB 示例 (调试 Frida C++ 代码):**

假设我们想查看 Frida 如何 hook `open()` 系统调用并将参数传递给 JavaScript。

1. **找到 Frida 源码中负责 `open()` hook 的位置。**  这需要对 Frida 的内部实现有一定的了解。
2. **使用 LLDB attach 到目标进程。**
3. **在 Frida 的 `open()` hook 函数入口处设置断点。** 例如：`b frida-agent.so` `函数名_of_open_hook`
4. **让目标进程执行文件打开操作。**
5. **当断点命中时，使用 LLDB 命令查看寄存器或内存，获取 `open()` 的参数 (文件名、flags 等)。**  例如：
    *   `register read` (查看寄存器内容，参数通常通过寄存器传递)
    *   `x/s 寄存器地址` (查看字符串参数)
6. **单步执行 Frida 的代码，查看 Frida 如何将这些参数转换为 JavaScript 对象。**  这可能涉及到查找 Frida 的 JavaScript 引擎交互相关的代码。
7. **在将数据传递给 JavaScript 的地方设置断点，查看传递的数据结构。**

**LLDB Python 脚本示例 (简化说明概念):**

```python
# 假设 Frida 的 C++ 代码中有一个名为 'send_to_javascript' 的函数负责向 JavaScript 发送数据

import lldb

def hook_open_and_print_args(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    # 设置在 Frida open hook 函数入口处的断点 (需要替换实际函数名)
    breakpoint = target.BreakpointCreateByName("frida-agent.so", "frida_open_hook_function")

    # 定义断点命中时的回调函数
    def breakpoint_callback(frame, bp_loc, dict):
        # 获取 open() 的参数 (假设参数在 rdi 和 rsi 寄存器中)
        filename_addr = frame.FindRegister("rdi").GetValueAsUnsigned()
        flags = frame.FindRegister("rsi").GetValueAsUnsigned()

        # 读取文件名字符串
        error = lldb.SBError()
        filename = process.ReadCStringFromMemory(filename_addr, 256, error)
        if error.Fail():
            filename = "Error reading filename"

        print(f"Intercepted open() call: filename='{filename}', flags={flags}")

        # 继续执行
        process.Continue()
        return False  # 返回 False 表示断点不需要被禁用

    # 设置断点命令，调用回调函数
    breakpoint.SetScriptCallbackFunction("breakpoint_callback")

    print("Breakpoint set on open() hook. Run the target process.")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f fs_debug.hook_open_and_print_args hook_open')
    print("The 'hook_open' command has been created.")

# 使用方法: 在 LLDB 中 attach 到目标进程后，运行命令 'hook_open'
```

**注意:**  这只是一个高度简化的概念示例。实际的 Frida 内部实现要复杂得多，需要更深入的分析才能编写出有效的 LLDB 调试脚本。

**5. 逻辑推理的假设输入与输出:**

假设 `fs_agent.js`  被配置为监控文件读取操作，并且只传递文件名和读取的字节数。

**假设输入 (来自 Frida instrumentation):**

```javascript
{
  type: "read",
  filename: "/home/user/document.txt",
  bytesRead: 1024
}
```

**可能的输出 (通过 `data` 事件发送):**

```javascript
{
  event: "file_read",
  file: "/home/user/document.txt",
  size: 1024
}
```

**逻辑推理:**  `fs_agent.js` 接收到表示文件读取事件的 JavaScript 对象，然后将其转换成一个更友好的格式，并只保留了文件名和读取的字节数信息。

**6. 涉及用户或编程常见的使用错误:**

*   **没有正确处理 `error` 事件:** 如果底层 Frida instrumentation 发生错误，或者在处理数据过程中出现异常，`fs_agent.js` 可能会发出 `error` 事件。用户如果没有监听并处理这个事件，可能会导致程序意外崩溃或数据丢失。
*   **背压问题:** 如果 `fs_agent.js` 作为可读流，下游消费者处理数据的速度跟不上，会导致内部缓冲区积压。如果用户没有正确地使用 `pipe` 或其他流控制机制，可能会导致内存占用过高。
*   **不理解数据格式:** 用户需要了解 `fs_agent.js` 输出的数据格式，才能正确地解析和使用这些数据。如果假设了错误的数据格式，会导致程序逻辑错误。
*   **资源泄漏:** 如果 `fs_agent.js` 在处理文件系统事件时打开了文件句柄或其他资源，但没有在适当的时候关闭或释放，可能会导致资源泄漏。 (虽然这段代码本身看不出来有直接的资源管理，但考虑到其功能，这是一个潜在的风险)。
*   **错误地实现 `_transform` (如果子类化):** 如果用户继承了 `Transform` 类并实现了自己的 `_transform` 方法，可能会因为逻辑错误导致数据处理不正确。

**7. 用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要监控目标应用程序的文件系统操作。**
2. **用户选择使用 Frida 进行动态 instrumentation。**
3. **用户编写 Frida 脚本。**  这个脚本可能需要导入或利用 `fs_agent.js` 提供的功能。
4. **用户在 Frida 脚本中指定了要 hook 的文件系统相关的函数或事件。**
5. **Frida 框架加载 `fs_agent.js` 到目标进程的 JavaScript 引擎中。**
6. **当目标应用程序执行被 hook 的文件系统操作时，Frida 的 instrumentation 代码会捕获这些操作的信息。**
7. **这些信息被传递到 `fs_agent.js` 的实例中。**
8. **用户可能会查看 `fs_agent.js` 的源代码，以了解它是如何处理这些信息的，或者进行调试。**  例如，用户可能想知道 `fs_agent.js` 输出了哪些数据，或者在哪个环节出现了问题。

**8. 归纳一下它的功能 (第8部分，共12部分):**

作为 Frida 文件系统监控 agent 的一部分，`fs_agent.js` 的核心功能是**提供一个流式的接口，用于处理来自底层 Frida instrumentation 代码的文件系统事件或数据。**  它可以作为数据源 (`Readable`) 将文件系统事件推送给其他模块，也可以作为数据转换器 (`Transform`) 对这些事件进行处理和格式化。  它的主要作用是**将底层的、原始的文件系统事件转化为更容易在 JavaScript 环境中处理和分析的数据流。**  在整个 Frida 文件系统监控的流程中，它很可能位于数据采集和数据消费之间，负责数据的初步处理和封装。

### 提示词
```
这是目录为frida/build/subprojects/frida-tools/agents/fs/fs_agent.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```javascript
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"}
✄
import{addAbortSignal as e}from"./add-abort-signal.js";import t from"./buffer_list.js";import*as r from"./destroy.js";import n from"./end-of-stream.js";import{aggregateTwoErrors as a,codes as i}from"../errors.js";import o from"./from.js";import{Stream as d,prependListener as s}from"./legacy.js";import{getHighWaterMark as l,getDefaultHighWaterMark as u}from"./state.js";import{Buffer as h}from"buffer";import c from"events";import f from"process";import{StringDecoder as b}from"string_decoder";export default Readable;const{ERR_INVALID_ARG_TYPE:p,ERR_METHOD_NOT_IMPLEMENTED:g,ERR_OUT_OF_RANGE:m,ERR_STREAM_PUSH_AFTER_EOF:y,ERR_STREAM_UNSHIFT_AFTER_END_EVENT:_}=i,w=Symbol("kPaused");Object.setPrototypeOf(Readable.prototype,d.prototype),Object.setPrototypeOf(Readable,d);const R=()=>{},{errorOrDestroy:S}=r;export function ReadableState(e,r,n){"boolean"!=typeof n&&(n=r instanceof d.Duplex),this.objectMode=!(!e||!e.objectMode),n&&(this.objectMode=this.objectMode||!(!e||!e.readableObjectMode)),this.highWaterMark=e?l(this,e,"readableHighWaterMark",n):u(!1),this.buffer=new t,this.length=0,this.pipes=[],this.flowing=null,this.ended=!1,this.endEmitted=!1,this.reading=!1,this.constructed=!0,this.sync=!0,this.needReadable=!1,this.emittedReadable=!1,this.readableListening=!1,this.resumeScheduled=!1,this[w]=null,this.errorEmitted=!1,this.emitClose=!e||!1!==e.emitClose,this.autoDestroy=!e||!1!==e.autoDestroy,this.destroyed=!1,this.errored=null,this.closed=!1,this.closeEmitted=!1,this.defaultEncoding=e&&e.defaultEncoding||"utf8",this.awaitDrainWriters=null,this.multiAwaitDrain=!1,this.readingMore=!1,this.dataEmitted=!1,this.decoder=null,this.encoding=null,e&&e.encoding&&(this.decoder=new b(e.encoding),this.encoding=e.encoding)}export function Readable(t){if(!(this instanceof Readable))return new Readable(t);const n=this instanceof d.Duplex;this._readableState=new ReadableState(t,this,n),t&&("function"==typeof t.read&&(this._read=t.read),"function"==typeof t.destroy&&(this._destroy=t.destroy),"function"==typeof t.construct&&(this._construct=t.construct),t.signal&&!n&&e(t.signal,this)),d.call(this,t),r.construct(this,(()=>{this._readableState.needReadable&&L(this,this._readableState)}))}function E(e,t,r,n){const a=e._readableState;let i;if(a.objectMode||("string"==typeof t?(r=r||a.defaultEncoding,a.encoding!==r&&(n&&a.encoding?t=h.from(t,r).toString(a.encoding):(t=h.from(t,r),r=""))):t instanceof h?r="":d._isUint8Array(t)?(t=d._uint8ArrayToBuffer(t),r=""):null!=t&&(i=new p("chunk",["string","Buffer","Uint8Array"],t))),i)S(e,i);else if(null===t)a.reading=!1,function(e,t){if(t.ended)return;if(t.decoder){const e=t.decoder.end();e&&e.length&&(t.buffer.push(e),t.length+=t.objectMode?1:e.length)}t.ended=!0,t.sync?j(e):(t.needReadable=!1,t.emittedReadable=!0,W(e))}(e,a);else if(a.objectMode||t&&t.length>0)if(n)if(a.endEmitted)S(e,new _);else{if(a.destroyed||a.errored)return!1;M(e,a,t,!0)}else if(a.ended)S(e,new y);else{if(a.destroyed||a.errored)return!1;a.reading=!1,a.decoder&&!r?(t=a.decoder.write(t),a.objectMode||0!==t.length?M(e,a,t,!1):L(e,a)):M(e,a,t,!1)}else n||(a.reading=!1,L(e,a));return!a.ended&&(a.length<a.highWaterMark||0===a.length)}function M(e,t,r,n){t.flowing&&0===t.length&&!t.sync&&e.listenerCount("data")>0?(t.multiAwaitDrain?t.awaitDrainWriters.clear():t.awaitDrainWriters=null,t.dataEmitted=!0,e.emit("data",r)):(t.length+=t.objectMode?1:r.length,n?t.buffer.unshift(r):t.buffer.push(r),t.needReadable&&j(e)),L(e,t)}Readable.prototype.destroy=r.destroy,Readable.prototype._undestroy=r.undestroy,Readable.prototype._destroy=function(e,t){t(e)},Readable.prototype[c.captureRejectionSymbol]=function(e){this.destroy(e)},Readable.prototype.push=function(e,t){return E(this,e,t,!1)},Readable.prototype.unshift=function(e,t){return E(this,e,t,!0)},Readable.prototype.isPaused=function(){const e=this._readableState;return!0===e[w]||!1===e.flowing},Readable.prototype.setEncoding=function(e){const t=new b(e);this._readableState.decoder=t,this._readableState.encoding=this._readableState.decoder.encoding;const r=this._readableState.buffer;let n="";for(const e of r)n+=t.write(e);return r.clear(),""!==n&&r.push(n),this._readableState.length=n.length,this};function D(e,t){return e<=0||0===t.length&&t.ended?0:t.objectMode?1:Number.isNaN(e)?t.flowing&&t.length?t.buffer.first().length:t.length:e<=t.length?e:t.ended?t.length:0}function j(e){const t=e._readableState;t.needReadable=!1,t.emittedReadable||(t.emittedReadable=!0,f.nextTick(W,e))}function W(e){const t=e._readableState;t.destroyed||t.errored||!t.length&&!t.ended||(e.emit("readable"),t.emittedReadable=!1),t.needReadable=!t.flowing&&!t.ended&&t.length<=t.highWaterMark,O(e)}function L(e,t){!t.readingMore&&t.constructed&&(t.readingMore=!0,f.nextTick(k,e,t))}function k(e,t){for(;!t.reading&&!t.ended&&(t.length<t.highWaterMark||t.flowing&&0===t.length);){const r=t.length;if(e.read(0),r===t.length)break}t.readingMore=!1}function v(e){const t=e._readableState;t.readableListening=e.listenerCount("readable")>0,t.resumeScheduled&&!1===t[w]?t.flowing=!0:e.listenerCount("data")>0?e.resume():t.readableListening||(t.flowing=null)}function T(e){e.read(0)}function A(e,t){t.reading||e.read(0),t.resumeScheduled=!1,e.emit("resume"),O(e),t.flowing&&!t.reading&&e.read(0)}function O(e){const t=e._readableState;for(;t.flowing&&null!==e.read(););}function x(e,t){"function"!=typeof e.read&&(e=Readable.wrap(e,{objectMode:!0}));const i=async function*(e,t){let i,o=R;function d(t){this===e?(o(),o=R):o=t}e.on("readable",d),n(e,{writable:!1},(e=>{i=e?a(i,e):null,o(),o=R}));try{for(;;){const t=e.destroyed?null:e.read();if(null!==t)yield t;else{if(i)throw i;if(null===i)return;await new Promise(d)}}}catch(e){throw i=a(i,e),i}finally{!i&&!1===t?.destroyOnReturn||void 0!==i&&!e._readableState.autoDestroy||r.destroyer(e,null)}}(e,t);return i.stream=e,i}function N(e,t){if(0===t.length)return null;let r;return t.objectMode?r=t.buffer.shift():!e||e>=t.length?(r=t.decoder?t.buffer.join(""):1===t.buffer.length?t.buffer.first():t.buffer.concat(t.length),t.buffer.clear()):r=t.buffer.consume(e,t.decoder),r}function P(e){const t=e._readableState;t.endEmitted||(t.ended=!0,f.nextTick(C,t,e))}function C(e,t){if(!e.errored&&!e.closeEmitted&&!e.endEmitted&&0===e.length)if(e.endEmitted=!0,t.emit("end"),t.writable&&!1===t.allowHalfOpen)f.nextTick(U,t);else if(e.autoDestroy){const e=t._writableState;(!e||e.autoDestroy&&(e.finished||!1===e.writable))&&t.destroy()}}function U(e){e.writable&&!e.writableEnded&&!e.destroyed&&e.end()}Readable.prototype.read=function(e){void 0===e?e=NaN:Number.isInteger(e)||(e=Number.parseInt(e,10));const t=this._readableState,r=e;if(e>t.highWaterMark&&(t.highWaterMark=function(e){if(e>1073741824)throw new m("size","<= 1GiB",e);return e--,e|=e>>>1,e|=e>>>2,e|=e>>>4,e|=e>>>8,e|=e>>>16,++e}(e)),0!==e&&(t.emittedReadable=!1),0===e&&t.needReadable&&((0!==t.highWaterMark?t.length>=t.highWaterMark:t.length>0)||t.ended))return 0===t.length&&t.ended?P(this):j(this),null;if(0===(e=D(e,t))&&t.ended)return 0===t.length&&P(this),null;let n,a=t.needReadable;if((0===t.length||t.length-e<t.highWaterMark)&&(a=!0),t.ended||t.reading||t.destroyed||t.errored||!t.constructed)a=!1;else if(a){t.reading=!0,t.sync=!0,0===t.length&&(t.needReadable=!0);try{const e=this._read(t.highWaterMark);if(null!=e){const t=e.then;"function"==typeof t&&t.call(e,R,(function(e){S(this,e)}))}}catch(e){S(this,e)}t.sync=!1,t.reading||(e=D(r,t))}return n=e>0?N(e,t):null,null===n?(t.needReadable=t.length<=t.highWaterMark,e=0):(t.length-=e,t.multiAwaitDrain?t.awaitDrainWriters.clear():t.awaitDrainWriters=null),0===t.length&&(t.ended||(t.needReadable=!0),r!==e&&t.ended&&P(this)),null===n||t.errorEmitted||t.closeEmitted||(t.dataEmitted=!0,this.emit("data",n)),n},Readable.prototype._read=function(e){throw new g("_read()")},Readable.prototype.pipe=function(e,t){const r=this,n=this._readableState;1===n.pipes.length&&(n.multiAwaitDrain||(n.multiAwaitDrain=!0,n.awaitDrainWriters=new Set(n.awaitDrainWriters?[n.awaitDrainWriters]:[]))),n.pipes.push(e);const a=(!t||!1!==t.end)&&e!==f.stdout&&e!==f.stderr?o:m;function i(t,a){t===r&&a&&!1===a.hasUnpiped&&(a.hasUnpiped=!0,function(){e.removeListener("close",p),e.removeListener("finish",g),d&&e.removeListener("drain",d);e.removeListener("error",b),e.removeListener("unpipe",i),r.removeListener("end",o),r.removeListener("end",m),r.removeListener("data",h),l=!0,d&&n.awaitDrainWriters&&(!e._writableState||e._writableState.needDrain)&&d()}())}function o(){e.end()}let d;n.endEmitted?f.nextTick(a):r.once("end",a),e.on("unpipe",i);let l=!1;function u(){l||(1===n.pipes.length&&n.pipes[0]===e?(n.awaitDrainWriters=e,n.multiAwaitDrain=!1):n.pipes.length>1&&n.pipes.includes(e)&&n.awaitDrainWriters.add(e),r.pause()),d||(d=function(e,t){return function(){const r=e._readableState;r.awaitDrainWriters===t?r.awaitDrainWriters=null:r.multiAwaitDrain&&r.awaitDrainWriters.delete(t),r.awaitDrainWriters&&0!==r.awaitDrainWriters.size||!c.listenerCount(e,"data")||(r.flowing=!0,O(e))}}(r,e),e.on("drain",d))}function h(t){!1===e.write(t)&&u()}function b(t){if(m(),e.removeListener("error",b),0===c.listenerCount(e,"error")){const r=e._writableState||e._readableState;r&&!r.errorEmitted?S(e,t):e.emit("error",t)}}function p(){e.removeListener("finish",g),m()}function g(){e.removeListener("close",p),m()}function m(){r.unpipe(e)}return r.on("data",h),s(e,"error",b),e.once("close",p),e.once("finish",g),e.emit("pipe",r),!0===e.writableNeedDrain?n.flowing&&u():n.flowing||r.resume(),e},Readable.prototype.unpipe=function(e){const t=this._readableState;if(0===t.pipes.length)return this;if(!e){const e=t.pipes;t.pipes=[],this.pause();for(let t=0;t<e.length;t++)e[t].emit("unpipe",this,{hasUnpiped:!1});return this}const r=t.pipes.indexOf(e);return-1===r||(t.pipes.splice(r,1),0===t.pipes.length&&this.pause(),e.emit("unpipe",this,{hasUnpiped:!1})),this},Readable.prototype.on=function(e,t){const r=d.prototype.on.call(this,e,t),n=this._readableState;return"data"===e?(n.readableListening=this.listenerCount("readable")>0,!1!==n.flowing&&this.resume()):"readable"===e&&(n.endEmitted||n.readableListening||(n.readableListening=n.needReadable=!0,n.flowing=!1,n.emittedReadable=!1,n.length?j(this):n.reading||f.nextTick(T,this))),r},Readable.prototype.addListener=Readable.prototype.on,Readable.prototype.removeListener=function(e,t){const r=d.prototype.removeListener.call(this,e,t);return"readable"===e&&f.nextTick(v,this),r},Readable.prototype.off=Readable.prototype.removeListener,Readable.prototype.removeAllListeners=function(e){const t=d.prototype.removeAllListeners.apply(this,arguments);return"readable"!==e&&void 0!==e||f.nextTick(v,this),t},Readable.prototype.resume=function(){const e=this._readableState;return e.flowing||(e.flowing=!e.readableListening,function(e,t){t.resumeScheduled||(t.resumeScheduled=!0,f.nextTick(A,e,t))}(this,e)),e[w]=!1,this},Readable.prototype.pause=function(){return!1!==this._readableState.flowing&&(this._readableState.flowing=!1,this.emit("pause")),this._readableState[w]=!0,this},Readable.prototype.wrap=function(e){let t=!1;e.on("data",(r=>{!this.push(r)&&e.pause&&(t=!0,e.pause())})),e.on("end",(()=>{this.push(null)})),e.on("error",(e=>{S(this,e)})),e.on("close",(()=>{this.destroy()})),e.on("destroy",(()=>{this.destroy()})),this._read=()=>{t&&e.resume&&(t=!1,e.resume())};const r=Object.keys(e);for(let t=1;t<r.length;t++){const n=r[t];void 0===this[n]&&"function"==typeof e[n]&&(this[n]=e[n].bind(e))}return this},Readable.prototype[Symbol.asyncIterator]=function(){return x(this)},Readable.prototype.iterator=function(e){return x(this,e)},Object.defineProperties(Readable.prototype,{readable:{get(){const e=this._readableState;return!(!e||!1===e.readable||e.destroyed||e.errorEmitted||e.endEmitted)},set(e){this._readableState&&(this._readableState.readable=!!e)}},readableDidRead:{enumerable:!1,get:function(){return this._readableState.dataEmitted}},readableAborted:{enumerable:!1,get:function(){return!(!this._readableState.destroyed&&!this._readableState.errored||this._readableState.endEmitted)}},readableHighWaterMark:{enumerable:!1,get:function(){return this._readableState.highWaterMark}},readableBuffer:{enumerable:!1,get:function(){return this._readableState&&this._readableState.buffer}},readableFlowing:{enumerable:!1,get:function(){return this._readableState.flowing},set:function(e){this._readableState&&(this._readableState.flowing=e)}},readableLength:{enumerable:!1,get(){return this._readableState.length}},readableObjectMode:{enumerable:!1,get(){return!!this._readableState&&this._readableState.objectMode}},readableEncoding:{enumerable:!1,get(){return this._readableState?this._readableState.encoding:null}},destroyed:{enumerable:!1,get(){return void 0!==this._readableState&&this._readableState.destroyed},set(e){this._readableState&&(this._readableState.destroyed=e)}},readableEnded:{enumerable:!1,get(){return!!this._readableState&&this._readableState.endEmitted}}}),Object.defineProperties(ReadableState.prototype,{pipesCount:{get(){return this.pipes.length}},paused:{get(){return!1!==this[w]},set(e){this[w]=!!e}}}),Readable._fromList=N,Readable.from=function(e,t){return o(Readable,e,t)},Readable.wrap=function(e,t){return new Readable({objectMode:e.readableObjectMode??e.objectMode??!0,...t,destroy(t,n){r.destroyer(e,t),n(t)}}).wrap(e)};
✄
{"version":3,"file":"state.js","names":["errorCodes","ERR_INVALID_ARG_VALUE","getDefaultHighWaterMark","objectMode","getHighWaterMark","state","options","duplexKey","isDuplex","hwm","highWaterMark","highWaterMarkFrom","Number","isInteger","Math","floor"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"gBAAkBA,MAAkB,eAEpC,MAAMC,sBAAEA,GAA0BD,SAO3B,SAASE,wBAAwBC,GACtC,OAAOA,EAAa,GAAK,KAC3B,QAEO,SAASC,iBAAiBC,EAAOC,EAASC,EAAWC,GAC1D,MAAMC,EAVR,SAA2BH,EAASE,EAAUD,GAC5C,OAAgC,MAAzBD,EAAQI,cAAwBJ,EAAQI,cAC7CF,EAAWF,EAAQC,GAAa,IACpC,CAOcI,CAAkBL,EAASE,EAAUD,GACjD,GAAW,MAAPE,EAAa,CACf,IAAKG,OAAOC,UAAUJ,IAAQA,EAAM,EAAG,CAErC,MAAM,IAAIR,EADGO,EAAW,WAAWD,IAAc,wBACXE,EACxC,CACA,OAAOK,KAAKC,MAAMN,EACpB,CAGA,OAAOP,wBAAwBG,EAAMF,WACvC"}
✄
import{codes as r}from"../errors.js";const{ERR_INVALID_ARG_VALUE:t}=r;export function getDefaultHighWaterMark(r){return r?16:16384}export function getHighWaterMark(r,e,o,n){const a=function(r,t,e){return null!=r.highWaterMark?r.highWaterMark:t?r[e]:null}(e,n,o);if(null!=a){if(!Number.isInteger(a)||a<0){throw new t(n?`options.${o}`:"options.highWaterMark",a)}return Math.floor(a)}return getDefaultHighWaterMark(r.objectMode)}
✄
{"version":3,"file":"transform.js","names":["Duplex","errorCodes","process","ERR_METHOD_NOT_IMPLEMENTED","Object","setPrototypeOf","Transform","prototype","kCallback","Symbol","options","this","call","_readableState","sync","transform","_transform","flush","_flush","on","prefinish","final","cb","called","destroyed","push","result","er","data","destroy","then","nextTick","err","_final","chunk","encoding","callback","_write","rState","wState","_writableState","length","val","ended","highWaterMark","undefined","_read"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"OA+DOA,MAAY,8BACDC,MAAkB,sBAE7BC,MAAa,UAEpB,MAAMC,2BACJA,GACEF,EAEJG,OAAOC,eAAeC,EAAUC,UAAWP,EAAOO,WAClDH,OAAOC,eAAeC,EAAWN,GAEjC,MAAMQ,EAAYC,OAAO,4BAEV,SAASH,EAAUI,GAChC,KAAMC,gBAAgBL,GACpB,OAAO,IAAIA,EAAUI,GAEvBV,EAAOY,KAAKD,KAAMD,GAKlBC,KAAKE,eAAeC,MAAO,EAE3BH,KAAKH,GAAa,KAEdE,IAC+B,mBAAtBA,EAAQK,YACjBJ,KAAKK,WAAaN,EAAQK,WAEC,mBAAlBL,EAAQO,QACjBN,KAAKO,OAASR,EAAQO,QAO1BN,KAAKQ,GAAG,YAAaC,EACvB,CAEA,SAASC,EAAMC,GACb,IAAIC,GAAS,EACb,GAA2B,mBAAhBZ,KAAKO,QAA0BP,KAAKa,UAgD7Cb,KAAKc,KAAK,MACNH,GACFA,QAlDsD,CACxD,MAAMI,EAASf,KAAKO,QAAO,CAACS,EAAIC,KAC9BL,GAAS,EACLI,EACEL,EACFA,EAAGK,GAEHhB,KAAKkB,QAAQF,IAKL,MAARC,GACFjB,KAAKc,KAAKG,GAEZjB,KAAKc,KAAK,MACNH,GACFA,IACF,IAEF,GAAII,QACF,IACE,MAAMI,EAAOJ,EAAOI,KACA,mBAATA,GACTA,EAAKlB,KACHc,GACCE,IACKL,IAEQ,MAARK,GACFjB,KAAKc,KAAKG,GACZjB,KAAKc,KAAK,MACNH,GACFpB,EAAQ6B,SAAST,GAAG,IAEvBU,IACKV,EACFpB,EAAQ6B,SAAST,EAAIU,GAErB9B,EAAQ6B,UAAS,IAAMpB,KAAKkB,QAAQG,IACtC,GAKR,CAFE,MAAOA,GACP9B,EAAQ6B,UAAS,IAAMpB,KAAKkB,QAAQG,IACtC,CAEJ,CAMF,CAEA,SAASZ,IACHT,KAAKsB,SAAWZ,GAClBA,EAAMT,KAAKD,KAEf,CAEAL,EAAUC,UAAU0B,OAASZ,EAE7Bf,EAAUC,UAAUS,WAAa,SAASkB,EAAOC,EAAUC,GACzD,MAAM,IAAIjC,EAA2B,eACvC,EAEAG,EAAUC,UAAU8B,OAAS,SAASH,EAAOC,EAAUC,GACrD,MAAME,EAAS3B,KAAKE,eACd0B,EAAS5B,KAAK6B,eACdC,EAASH,EAAOG,OAEtB,IAAIlB,GAAS,EACb,MAAMG,EAASf,KAAKK,WAAWkB,EAAOC,GAAU,CAACH,EAAKU,KACpDnB,GAAS,EACLS,EACFI,EAASJ,IAIA,MAAPU,GACF/B,KAAKc,KAAKiB,GAIVH,EAAOI,OACPF,IAAWH,EAAOG,QAClBH,EAAOG,OAASH,EAAOM,eACL,IAAlBN,EAAOG,OAEPL,IAEAzB,KAAKH,GAAa4B,EACpB,IAEF,QAAeS,IAAXnB,GAAkC,MAAVA,EAC1B,IACE,MAAMI,EAAOJ,EAAOI,KACA,mBAATA,GACTA,EAAKlB,KACHc,GACCgB,IACKnB,IAGO,MAAPmB,GACF/B,KAAKc,KAAKiB,GAIVH,EAAOI,OACPF,IAAWH,EAAOG,QAClBH,EAAOG,OAASH,EAAOM,eACL,IAAlBN,EAAOG,OACPvC,EAAQ6B,SAASK,GAEjBzB,KAAKH,GAAa4B,EACpB,IAEDJ,IACC9B,EAAQ6B,SAASK,EAAUJ,EAAI,GAKvC,CAFE,MAAOA,GACP9B,EAAQ6B,SAASK,EAAUJ,EAC7B,CAEJ,EAEA1B,EAAUC,UAAUuC,MAAQ,WAC1B,GAAInC,KAAKH,GAAY,CACnB,MAAM4B,EAAWzB,KAAKH,GACtBG,KAAKH,GAAa,KAClB4B,GACF,CACF"}
✄
import t from"./duplex.js";import{codes as n}from"../errors.js";import s from"process";const{ERR_METHOD_NOT_IMPLEMENTED:e}=n;Object.setPrototypeOf(o.prototype,t.prototype),Object.setPrototypeOf(o,t);const i=Symbol("kCallback");export default function o(n){if(!(this instanceof o))return new o(n);t.call(this,n),this._readableState.sync=!1,this[i]=null,n&&("function"==typeof n.transform&&(this._transform=n.transform),"function"==typeof n.flush&&(this._flush=n.flush)),this.on("prefinish",l)}function h(t){let n=!1;if("function"!=typeof this._flush||this.destroyed)this.push(null),t&&t();else{const e=this._flush(((s,e)=>{n=!0,s?t?t(s):this.destroy(s):(null!=e&&this.push(e),this.push(null),t&&t())}));if(null!=e)try{const i=e.then;"function"==typeof i&&i.call(e,(e=>{n||(null!=e&&this.push(e),this.push(null),t&&s.nextTick(t))}),(n=>{t?s.nextTick(t,n):s.nextTick((()=>this.destroy(n)))}))}catch(t){s.nextTick((()=>this.destroy(t)))}}}function l(){this._final!==h&&h.call(this)}o.prototype._final=h,o.prototype._transform=function(t,n,s){throw new e("_transform()")},o.prototype._write=function(t,n,e){const o=this._readableState,h=this._writableState,l=o.length;let r=!1;const f=this._transform(t,n,((t,n)=>{r=!0,t?e(t):(null!=n&&this.push(n),h.ended||l===o.length||o.length<o.highWaterMark||0===o.length?e():this[i]=e)}));if(void 0!==f&&null!=f)try{const t=f.then;"function"==typeof t&&t.call(f,(t=>{r||(null!=t&&this.push(t),h.ended||l===o.length||o.length<o.highWaterMark||0===o.length?s.nextTick(e):this[i]=e)}),(t=>{s.nextTick(e,t)}))}catch(t){s.nextTick(e,t)}},o.prototype._read=function(){if(this[i]){const t=this[i];this[i]=null,t()}};
✄
{"version":3,"file":"utils.js","names":["kDestroyed","Symbol","kIsDisturbed","isReadableNodeStream","obj","pipe","on","_writableState","_readableState","readable","isWritableNodeStream","write","writable","isDuplexNodeStream","isNodeStream","isIterable","isAsync","asyncIterator","iterator","isDestroyed","stream","wState","rState","state","destroyed","isWritableEnded","writableEnded","errored","ended","isWritableFinished","strict","writableFinished","finished","length","isReadableEnded","readableEnded","isReadableFinished","endEmitted","isReadable","r","isWritable","isFinished","opts","isClosed","closed","_closed","isOutgoingMessage","_defaultKeepAlive","_removedConnection","_removedContLen","isServerResponse","_sent100","isServerRequest","_consuming","_dumped","undefined","req","upgradeOrConnect","willEmitClose","autoDestroy","emitClose","isDisturbed","readableDidRead","readableAborted"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"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"}
✄
export const kDestroyed=Symbol("kDestroyed");export const kIsDisturbed=Symbol("kIsDisturbed");export function isReadableNodeStream(e){return!(!e||"function"!=typeof e.pipe||"function"!=typeof e.on||e._writableState&&!1===e._readableState?.readable||e._writableState&&!e._readableState)}export function isWritableNodeStream(e){return!(!e||"function"!=typeof e.write||"function"!=typeof e.on||e._readableState&&!1===e._writableState?.writable)}export function isDuplexNodeStream(e){return!(!e||"function"!=typeof e.pipe||!e._readableState||"function"!=typeof e.on||"function"!=typeof e.write)}export function isNodeStream(e){return e&&(e._readableState||e._writableState||"function"==typeof e.write&&"function"==typeof e.on||"function"==typeof e.pipe&&"function"==typeof e.on)}export function isIterable(e,t){return null!=e&&(!0===t?"function"==typeof e[Symbol.asyncIterator]:!1===t?"function"==typeof e[Symbol.iterator]:"function"==typeof e[Symbol.asyncIterator]||"function"==typeof e[Symbol.iterator])}export function isDestroyed(e){if(!isNodeStream(e))return null;const t=e._writableState,o=e._readableState,n=t||o;return!!(e.destroyed||e[kDestroyed]||n?.destroyed)}export function isWritableEnded(e){if(!isWritableNodeStream(e))return null;if(!0===e.writableEnded)return!0;const t=e._writableState;return!t?.errored&&("boolean"!=typeof t?.ended?null:t.ended)}export function isWritableFinished(e,t){if(!isWritableNodeStream(e))return null;if(!0===e.writableFinished)return!0;const o=e._writableState;return!o?.errored&&("boolean"!=typeof o?.finished?null:!!(o.finished||!1===t&&!0===o.ended&&0===o.length))}export function isReadableEnded(e){if(!isReadableNodeStream(e))return null;if(!0===e.readableEnded)return!0;const t=e._readableState;return!(!t||t.errored)&&("boolean"!=typeof t?.ended?null:t.ended)}export function isReadableFinished(e,t){if(!isReadableNodeStream(e))return null;const o=e._readableState;return!o?.errored&&("boolean"!=typeof o?.endEmitted?null:!!(o.endEmitted||!1===t&&!0===o.ended&&0===o.length))}export function isReadable(e){const t=isReadableNodeStream(e);return null===t||"boolean"!=typeof e?.readable?null:!isDestroyed(e)&&(t&&e.readable&&!isReadableFinished(e))}export function isWritable(e){const t=isWritableNodeStream(e);return null===t||"boolean"!=typeof e?.writable?null:!isDestroyed(e)&&(t&&e.writable&&!isWritableEnded(e))}export function isFinished(e,t){return isNodeStream(e)?!!isDestroyed(e)||(!1===t?.readable||!isReadable(e))&&(!1===t?.writable||!isWritable(e)):null}export function isClosed(t){if(!isNodeStream(t))return null;const o=t._writableState,n=t._readableState;return"boolean"==typeof o?.closed||"boolean"==typeof n?.closed?o?.closed||n?.closed:"boolean"==typeof t._closed&&e(t)?t._closed:null}function e(e){return"boolean"==typeof e._closed&&"boolean"==typeof e._defaultKeepAlive&&"boolean"==typeof e._removedConnection&&"boolean"==typeof e._removedContLen}export function isServerResponse(t){return"boolean"==typeof t._sent100&&e(t)}export function isServerRequest(e){return"boolean"==typeof e._consuming&&"boolean"==typeof e._dumped&&void 0===e.req?.upgradeOrConnect}export function willEmitClose(e){if(!isNodeStream(e))return null;const t=e._writableState,o=e._readableState,n=t||o;return!n&&isServerResponse(e)||!!(n&&n.autoDestroy&&n.emitClose&&!1===n.closed)}export function isDisturbed(e){return!(!e||!(e.readableDidRead||e.readableAborted||e[kIsDisturbed]))}
✄
{"version":3,"file":"writable.js","names":["addAbortSignal","destroyImpl","errorCodes","Stream","getHighWaterMark","getDefaultHighWaterMark","Buffer","EE","process","Writable","ERR_INVALID_ARG_TYPE","ERR_METHOD_NOT_IMPLEMENTED","ERR_MULTIPLE_CALLBACK","ERR_STREAM_CANNOT_PIPE","ERR_STREAM_DESTROYED","ERR_STREAM_ALREADY_FINISHED","ERR_STREAM_NULL_VALUES","ERR_STREAM_WRITE_AFTER_END","ERR_UNKNOWN_ENCODING","errorOrDestroy","nop","Object","setPrototypeOf","prototype","kOnFinished","Symbol","WritableState","options","stream","isDuplex","Duplex","this","objectMode","writableObjectMode","highWaterMark","finalCalled","needDrain","ending","ended","finished","destroyed","noDecode","decodeStrings","defaultEncoding","length","writing","corked","sync","bufferProcessing","onwrite","bind","undefined","writecb","writelen","afterWriteTickInfo","resetBuffer","pendingcb","constructed","prefinished","errorEmitted","emitClose","autoDestroy","errored","closed","closeEmitted","state","buffered","bufferedIndex","allBuffers","allNoop","getBuffer","slice","defineProperty","get","realHasInstance","Function","hasInstance","call","_writableState","write","_write","writev","_writev","destroy","_destroy","final","_final","construct","_construct","signal","clearBuffer","finishMaybe","chunk","encoding","cb","isEncoding","from","_isUint8Array","_uint8ArrayToBuffer","err","nextTick","callback","len","ret","push","writeOrBuffer","doWrite","onwriteError","er","errorBuffer","stack","_readableState","count","afterWriteTick","afterWrite","emit","n","onfinishCallbacks","splice","i","bufferedLength","chunks","needFinish","prefinish","called","onFinish","finish","result","then","callFinal","rState","endEmitted","readable","value","object","pipe","cork","uncork","setDefaultEncoding","toLowerCase","end","Error","defineProperties","set","writable","w","val","writableFinished","writableBuffer","writableEnded","writableNeedDrain","wState","writableHighWaterMark","writableCorked","writableLength","_undestroy","undestroy","captureRejectionSymbol"],"sourceRoot":"/root/frida/build/subprojects/frida-tools/agents/fs/fs_agent.js.p/node_modules/@frida/readable-stream/lib/","sources":[""],"mappings":"yBAyBSA,MAAsB,kCACnBC,MAAiB,+BACXC,MAAkB,gCAC3BC,MAAc,yCAErBC,6BACAC,MACK,8BAEEC,MAAc,gBAChBC,MAAQ,gBACRC,MAAa,yBAELC,SAEf,MAAMC,qBACJA,EAAoBC,2BACpBA,EAA0BC,sBAC1BA,EAAqBC,uBACrBA,EAAsBC,qBACtBA,EAAoBC,4BACpBA,EAA2BC,uBAC3BA,EAAsBC,2BACtBA,EAA0BC,qBAC1BA,GACEhB,GAEEiB,eAAEA,GAAmBlB,EAK3B,SAASmB,IAAO,CAHhBC,OAAOC,eAAeb,SAASc,UAAWpB,EAAOoB,WACjDF,OAAOC,eAAeb,SAAUN,GAIhC,MAAMqB,EAAcC,OAAO,sBAEpB,SAASC,cAAcC,EAASC,EAAQC,GAMrB,kBAAbA,IACTA,EAAWD,aAAkBzB,EAAO2B,QAItCC,KAAKC,cAAgBL,IAAWA,EAAQK,YAEpCH,IACFE,KAAKC,WAAaD,KAAKC,eAClBL,IAAWA,EAAQM,qBAK1BF,KAAKG,cAAgBP,EACnBvB,EAAiB2B,KAAMJ,EAAS,wBAAyBE,GACzDxB,GAAwB,GAG1B0B,KAAKI,aAAc,EAGnBJ,KAAKK,WAAY,EAEjBL,KAAKM,QAAS,EAEdN,KAAKO,OAAQ,EAEbP,KAAKQ,UAAW,EAGhBR,KAAKS,WAAY,EAKjB,MAAMC,KAAcd,IAAqC,IAA1BA,EAAQe,eACvCX,KAAKW,eAAiBD,EAKtBV,KAAKY,gBAAmBhB,GAAWA,EAAQgB,iBAAoB,OAK/DZ,KAAKa,OAAS,EAGdb,KAAKc,SAAU,EAGfd,KAAKe,OAAS,EAMdf,KAAKgB,MAAO,EAKZhB,KAAKiB,kBAAmB,EAGxBjB,KAAKkB,QAAUA,EAAQC,UAAKC,EAAWvB,GAGvCG,KAAKqB,QAAU,KAGfrB,KAAKsB,SAAW,EAIhBtB,KAAKuB,mBAAqB,KAE1BC,EAAYxB,MAIZA,KAAKyB,UAAY,EAMjBzB,KAAK0B,aAAc,EAInB1B,KAAK2B,aAAc,EAGnB3B,KAAK4B,cAAe,EAGpB5B,KAAK6B,WAAajC,IAAiC,IAAtBA,EAAQiC,UAGrC7B,KAAK8B,aAAelC,IAAmC,IAAxBA,EAAQkC,YAKvC9B,KAAK+B,QAAU,KAGf/B,KAAK
```