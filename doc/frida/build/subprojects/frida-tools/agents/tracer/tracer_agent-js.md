Response:
Let's break down the thought process to analyze the provided JavaScript code and answer the request.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of a Frida agent's tracer. It specifically wants to know about low-level interactions (binary, kernel), examples using LLDB, handling of errors, user steps to reach this code, and a summary of the functionality. The request is explicitly for "Part 1" and asks for a summary.

**2. High-Level Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable keywords and patterns related to dynamic instrumentation and tracing. Some obvious ones jump out:

* `"use strict"`:  Indicates modern JavaScript.
* `frida`: Though not explicitly used as a global, the file path hints at its involvement. The code interacts with `send`, `recv`, `Interceptor`, `Java`, `DebugSymbol`, `Module`, `ApiResolver`, and `Script`, all core Frida APIs.
* `trace`, `tracer`, `handlers`, `events`, `backtraces`: These strongly suggest the code is involved in collecting information about program execution.
* `native`, `java`, `objc`, `swift`:  Indicates the tracer supports multiple platforms/runtimes.
* `module`, `function`, `instruction`, `method`: These are the units of code being targeted for tracing.
* `include`, `exclude`:  Indicates filtering or selection of what to trace.
* `onEnter`, `onLeave`:  Common hooks for function tracing.
* `flush`: Suggests buffering and periodic sending of collected data.
* `Memory`, `address`:  Points to interaction with memory.
* `Thread`: Indicates awareness of multi-threading.

**3. Identifying Key Classes and Their Roles:**

The code defines a central class, `r` (presumably standing for "tracer" or something similar). This class appears to manage the entire tracing process. Let's analyze its key methods:

* **`constructor`**: Initializes data structures (maps for handlers, targets, stack depth, etc.), timers, and event queues. It also defines a default error handler.
* **`init`**: Sets up the agent environment, loads user-defined scripts, and starts the tracing process. It returns information about the target process.
* **`dispose`**: Cleans up resources, primarily by flushing pending events.
* **`updateHandlerCode`**: Modifies the JavaScript code associated with a specific tracepoint (handler). This suggests dynamic modification of tracing behavior.
* **`updateHandlerConfig`**: Changes the configuration of a tracepoint (e.g., muting, capturing backtraces).
* **`stageTargets`**: Creates a "plan" of what to trace without immediately activating it. This allows for pre-computation and potentially user review/modification.
* **`commitTargets`**:  Activates the tracing based on the staged plan. It differentiates between native and Java targets.
* **`readMemory`**:  Allows reading arbitrary memory, a crucial debugging feature.
* **`resolveAddresses`**: Converts memory addresses to symbolic names.
* **`cropStagedPlan`**:  Allows selecting a subset of the staged targets, useful for focusing on specific areas.
* **`start`**:  The main entry point to start tracing based on an initial set of targets.
* **`createPlan`**:  Parses the user's tracing requests (include/exclude rules for modules, functions, etc.) and builds a plan of targets to instrument.
* **`traceNativeTargets`**:  Handles the actual instrumentation of native (non-managed) code. It uses `Interceptor.attach`.
* **`traceJavaTargets`**: Handles the instrumentation of Java code, using `Java.perform` and modifying method implementations.
* **`makeNativeFunctionListener` / `makeNativeInstructionListener`**: Create the callback functions that are executed when traced native code is reached.
* **`makeJavaMethodWrapper`**: Creates a wrapper function around traced Java methods to intercept calls.
* **`handleJavaInvocation`**:  Handles the execution and return of traced Java methods.
* **`invokeNativeHandler` / `invokeJavaHandler`**:  Execute the user-provided JavaScript code associated with a tracepoint.
* **`updateDepth`**:  Manages the call stack depth for each thread.
* **`parseFunctionHandler` / `parseInstructionHandler` / `parseHandlerScript`**: Load and parse the user-provided JavaScript code for trace handlers.
* **`include...` / `exclude...` methods**:  Implement the logic for adding or removing specific targets from the trace plan based on different criteria (module names, function names, etc.).
* **`emit`**: Adds a tracing event to the pending queue.
* **`getModuleResolver` / `getObjcResolver` / `getSwiftResolver`**: Lazily initialize API resolvers to find modules, Objective-C methods, and Swift functions.

**4. Identifying Low-Level Interactions:**

Based on the keyword analysis and class method understanding, several low-level interactions become clear:

* **Binary Level:**
    * `Interceptor.attach`:  This is the core Frida API for hooking into native code. It directly manipulates the instruction stream, often by replacing the original instructions with a jump to the handler.
    * `Module.getBaseAddress`:  Accessing the base address of loaded modules is a low-level operation.
    * `DebugSymbol.fromAddress`:  Interacting with debugging symbols (DWARF, PDB) requires understanding binary formats.
    * `ptr(e).readVolatile(t)`: Directly reading memory at a given address.
* **Linux Kernel (Implicit):**
    * While not directly interacting with kernel APIs in *this specific agent code*, Frida itself (and thus this agent) relies on kernel-level mechanisms (like ptrace on Linux) to inject code and intercept execution. The agent's functionality wouldn't be possible without these underlying kernel features.
    * The concepts of processes, threads, and memory management are all fundamentally tied to the operating system kernel.

**5. Planning LLDB Examples:**

To replicate the functionality, we need to consider what the code *does*. It instruments code and executes JavaScript at those points. LLDB can't directly execute arbitrary JavaScript within the target process like Frida can. However, we can simulate aspects of it:

* **Setting Breakpoints:**  `Interceptor.attach` is analogous to setting breakpoints in LLDB. We can set breakpoints at the same addresses that Frida would instrument.
* **Examining Memory:** The `readMemory` function can be replicated with LLDB's `memory read` command (`x`).
* **Viewing Backtraces:**  `Thread.backtrace` is similar to LLDB's `bt` (backtrace) command.
* **Inspecting Registers/Arguments:**  The handler functions in the Frida code receive context information (registers, arguments). LLDB allows inspecting these.

**6. Considering User Errors and Steps:**

* **User Errors:**  Typos in module/function names, incorrect syntax in handler scripts, trying to trace Java when the JVM isn't present, trying to trace Objective-C/Swift when the runtime isn't loaded.
* **User Steps:**
    1. Write a Frida script that includes this agent.
    2. Define the targets to trace (modules, functions, etc.) using the agent's API.
    3. Optionally provide custom JavaScript code for the handlers.
    4. Run the Frida script, targeting a specific process.

**7. Structuring the Answer:**

Organize the findings into the requested sections: functionality, low-level examples, LLDB examples, user errors, user steps, and a summary.

**8. Refining and Reviewing:**

Review the generated answer for clarity, accuracy, and completeness. Ensure the LLDB examples are reasonable and demonstrate the equivalent concepts. Make sure the explanation of low-level interactions is precise. Double-check the summary accurately captures the main purpose of the code. Specifically, for the "Part 1" summary, focus on the core function of setting up the tracing environment and planning the instrumentation.

This detailed breakdown covers the thought process involved in analyzing the code and addressing the specific points in the request. The process involves understanding the code's purpose, identifying key components, recognizing low-level interactions, and figuring out how to relate that to a traditional debugger like LLDB.## Frida Tracer Agent 源文件功能解析 (第 1 部分)

这个 Frida 脚本文件 `tracer_agent.js` 的核心功能是**实现一个动态追踪器 (tracer)**。它允许用户指定需要追踪的目标（例如模块、函数、指令、Java 方法等），并在这些目标被执行时执行用户自定义的 JavaScript 代码，从而实现对程序运行时的监控和分析。

**以下是其主要功能的归纳：**

1. **目标管理和规划 (Target Management and Planning):**
   - **接收用户定义的追踪目标:**  通过 `init` 方法接收来自用户的追踪目标列表，这些目标可以是模块名、函数名、特定内存地址的指令、Objective-C/Swift 方法、Java 方法等。
   - **创建追踪计划 (Trace Plan):** `createPlan` 方法根据用户指定的追踪目标，构建一个详细的追踪计划，确定需要在哪些地址或方法上设置 hook。
   - **分阶段提交目标 (Staging and Committing Targets):**  `stageTargets` 允许用户先预演追踪计划，获取待追踪目标的 ID 列表，`commitTargets` 则最终提交并激活这些追踪目标。这提供了一种在实际 hook 之前预览和修改追踪目标的方式。
   - **支持包含和排除规则 (Include and Exclude Rules):** 用户可以指定要包含或排除的模块、函数等，从而更精细地控制追踪范围。

2. **动态 Hook 和代码注入 (Dynamic Hooking and Code Injection):**
   - **支持多种代码类型 (Multiple Code Types):** 可以 hook 本地 (native) 代码（汇编指令、C 函数、Objective-C/Swift 方法）以及 Java 代码。
   - **使用 Frida API 进行 Hook (Using Frida API for Hooking):**  内部使用了 Frida 的 `Interceptor.attach` 来 hook 本地代码，并使用 Java 桥接 (Java bridge) 来 hook Java 方法。
   - **执行用户自定义的 Handler 代码 (Executing User-defined Handler Code):** 当 hook 点被命中时，会执行用户提供的 JavaScript 代码（称为 handler），这些代码可以访问当时的上下文信息（例如寄存器、参数、返回值等）。

3. **事件管理和发送 (Event Management and Sending):**
   - **生成追踪事件 (Generating Trace Events):**  当 hook 点被触发时，会创建一个包含相关信息的事件，例如时间戳、线程 ID、调用栈、用户自定义的消息等。
   - **缓存和批量发送事件 (Caching and Batch Sending Events):**  `pendingEvents` 数组用于缓存生成的事件，并通过 `flush` 方法定期批量发送到 Frida 客户端。这提高了效率，避免频繁的单次发送。

4. **上下文信息捕获 (Context Information Capture):**
   - **捕获调用栈 (Capturing Call Stack):**  可以配置捕获 hook 发生时的调用栈信息 (`capture_backtraces`)。
   - **访问寄存器和参数 (Accessing Registers and Arguments):**  在 handler 代码中可以访问 hook 点的寄存器状态和函数参数。
   - **访问返回值 (Accessing Return Values):**  对于函数 hook，可以访问函数的返回值。

5. **内存操作 (Memory Operations):**
   - **读取内存 (Reading Memory):**  `readMemory` 方法允许读取指定地址的内存内容。
   - **解析地址 (Resolving Addresses):** `resolveAddresses` 方法可以将内存地址解析为符号信息（例如模块名和函数名）。

**涉及到的二进制底层和 Linux 内核 (Binary Level and Linux Kernel Involvement):**

* **二进制底层 (Binary Level):**
    - **`Interceptor.attach`:**  这个 Frida API 的核心功能就是在二进制层面修改目标进程的指令流，通常是在目标地址处插入跳转指令，将执行流导向 Frida 注入的 handler 代码。
    - **内存地址操作:** 代码中频繁出现对内存地址的操作，例如将字符串表示的地址转换为 `NativePointer` 对象 (`ptr(e)`), 进行地址加减运算 (`e.address.sub(s.base)`), 以及直接读取内存内容 (`ptr(e).readVolatile(t)`). 这些操作直接作用于进程的内存空间。
    - **调试符号 (Debug Symbols):**  `DebugSymbol.fromAddress` 用于从二进制文件中加载的调试符号信息中查找地址对应的函数名等信息。
    - **模块枚举 (Module Enumeration):**  代码中使用了 `Process.enumerateModules()` 和 `ModuleMap` 来获取和管理目标进程加载的模块信息，这涉及到读取操作系统维护的进程内存布局信息。

* **Linux 内核 (Linux Kernel):**
    - **Frida 的底层机制:**  虽然这个脚本本身没有直接调用 Linux 内核 API，但 Frida 作为一个动态插桩工具，其底层机制依赖于操作系统提供的功能，例如：
        - **ptrace:**  在 Linux 系统上，Frida 通常使用 `ptrace` 系统调用来注入代码、设置断点、读取/写入内存和寄存器等。
        - **进程和线程管理:**  代码中涉及到进程 ID (`Process.id`) 和线程 ID (`n.threadId`) 的获取和使用，这些信息是由操作系统内核管理的。
        - **内存管理:**  `Process.pageSize`  获取操作系统的内存页大小，这与内核的内存管理机制相关。
        - **动态链接器 (Dynamic Linker):**  `ApiResolver` 用于解析导入导出符号，这涉及到与动态链接器交互，获取符号的地址信息。

**lldb 指令或 lldb python 脚本复刻示例：**

假设 `tracer_agent.js` 中有以下代码，用于追踪 `libc.so` 模块中 `malloc` 函数的入口：

```javascript
M.init([["include", "function", "libc.so!malloc"]], {}, [], {});
```

可以使用以下 lldb 指令来复刻其部分功能（设置断点并在断点处打印信息）：

```lldb
# 设置断点在 malloc 函数入口
(lldb) b malloc

# 断点命中时执行的命令
(lldb) command script print('Hit malloc')

# 继续执行
(lldb) c
```

或者，使用 lldb Python 脚本可以实现更复杂的功能，例如：

```python
import lldb

def malloc_handler(debugger, command, result, internal_dict):
    print("Hit malloc")
    # 可以进一步获取寄存器或参数
    # target = debugger.GetSelectedTarget()
    # process = target.GetProcess()
    # thread = process.GetSelectedThread()
    # frame = thread.GetSelectedFrame()
    # arg0 = frame.GetArgumentAtIndex(0)
    # print(f"Argument 0: {arg0}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('breakpoint set -n malloc -C "script malloc_handler(debugger, command, result, internal_dict)"')
    print("Malloc breakpoint set with Python handler.")
```

将以上 Python 代码保存为 `malloc_breakpoint.py`，然后在 lldb 中执行：

```lldb
(lldb) command source malloc_breakpoint.py
```

**假设输入与输出 (Hypothetical Input and Output):**

假设用户想要追踪 `my_program` 进程中 `libutils.so` 模块的 `calculate_sum` 函数，并记录其参数。用户可能会提供如下配置给 Frida 客户端：

```json
{
  "target": "my_program",
  "agent": "./tracer_agent.js",
  "options": {
    "traceConfig": [
      ["include", "function", "libutils.so!calculate_sum"]
    ],
    "handlerCode": {
      "libutils.so!calculate_sum": {
        "onEnter": "function (args) { console.log('Entering calculate_sum, arg1: ' + args[0] + ', arg2: ' + args[1]); }"
      }
    }
  }
}
```

**假设输入：**  `my_program` 进程执行到 `libutils.so!calculate_sum` 函数，并且该函数被调用时，第一个参数值为 10，第二个参数值为 20。

**预期输出（在 Frida 客户端）：**

```
{"type":"events:add","events":[["<handler_id>",<timestamp>,<thread_id>,<depth>,"<return_address>",null,"Entering calculate_sum, arg1: 10, arg2: 20"]]}
```

（实际输出会包含具体的 handler ID、时间戳、线程 ID、返回地址等信息。）

**用户或编程常见的使用错误 (Common User or Programming Errors):**

1. **拼写错误 (Typos):**  在指定模块名、函数名时出现拼写错误，导致目标无法被正确匹配。例如，将 `libc.so` 拼写成 `libcs.so`。
2. **错误的符号 (Incorrect Symbols):**  指定了不存在的模块或函数名。例如，目标模块中根本没有名为 `non_existent_function` 的函数。
3. **Handler 代码错误 (Handler Code Errors):**  Handler 代码中包含语法错误或运行时错误，例如访问了不存在的变量，导致追踪过程异常。
4. **尝试追踪不存在的运行时 (Tracing Unavailable Runtimes):**  尝试追踪 Objective-C 或 Swift 代码，但目标进程并没有加载相应的运行时库。
5. **权限问题 (Permission Issues):** Frida 运行的权限不足以注入到目标进程。
6. **循环依赖 (Circular Dependencies) 在 Handler 中:**  Handler 代码中调用了可能再次触发相同 hook 的函数，导致无限递归。
7. **不正确的 Handler 参数使用:**  错误地访问或使用 `args` 对象中的参数，例如索引超出范围。

**用户操作如何一步步到达这里 (User Steps to Reach This Code):**

1. **安装 Frida 和 Frida 工具 (Install Frida and Frida Tools):** 用户首先需要在他们的系统上安装 Frida 核心库和相关的命令行工具（例如 `frida`）。
2. **编写 Frida 脚本 (Write Frida Script):** 用户需要编写一个 JavaScript 文件（例如 `my_tracer.js`），其中会包含 `tracer_agent.js` 的代码，并使用 `rpc.exports` 暴露 `init` 等接口。
3. **定义追踪配置 (Define Trace Configuration):** 在 Frida 脚本中，用户会通过调用 `M.init` 或 `M.stageTargets` 等方法，指定他们想要追踪的目标，例如模块、函数、指令等，以及相关的 Handler 代码。
4. **运行 Frida (Run Frida):** 用户使用 Frida 命令行工具 (`frida`) 或编程方式调用 Frida API，将编写好的脚本注入到目标进程中。例如：
   ```bash
   frida -p <process_id> -l my_tracer.js
   ```
   或者，如果目标是 Android 应用：
   ```bash
   frida -U -f <package_name> -l my_tracer.js
   ```
5. **目标进程执行到被追踪的代码 (Target Process Executes Traced Code):** 当目标进程执行到用户配置的追踪目标（例如某个函数被调用）时，`tracer_agent.js` 中设置的 hook 会被触发。
6. **执行 Handler 代码 (Execute Handler Code):**  hook 触发后，与该 hook 点关联的 Handler 代码会被执行。
7. **生成和发送事件 (Generate and Send Events):** Handler 代码执行过程中，或者在函数入口/出口，会生成追踪事件，这些事件会被缓存并通过 `send` 函数发送到 Frida 客户端。

**功能归纳 (Summary of Functionality):**

`tracer_agent.js` 的主要功能是**构建一个可配置的动态代码追踪框架**。它允许用户指定需要监控的目标代码片段（本地代码和 Java 代码），并在这些目标被执行时执行用户自定义的 JavaScript 代码，从而实现对程序运行时行为的精细化观察和分析。该脚本负责管理追踪目标、设置和管理 hook、捕获上下文信息以及将追踪事件发送到 Frida 客户端。它为用户提供了一种灵活且强大的方式来理解和调试程序的内部工作原理。

**这是第 1 部分，请记住还有第 2 部分的分析。** 在第 2 部分，可能会涉及到更具体的代码实现细节，例如 `parseFunctionHandler`、`makeNativeFunctionListener` 等函数的实现逻辑，以及更深入的错误处理和性能优化等方面的内容。

### 提示词
```
这是目录为frida/build/subprojects/frida-tools/agents/tracer/tracer_agent.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```javascript
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){(function (){
"use strict";

var e, t = this && this.__classPrivateFieldGet || function(e, t, s, n) {
  if ("a" === s && !n) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !n : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === s ? n : "a" === s ? n.call(e) : n ? n.value : t.get(e);
}, s = this && this.__classPrivateFieldSet || function(e, t, s, n, r) {
  if ("m" === n) throw new TypeError("Private method is not writable");
  if ("a" === n && !r) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === n ? r.call(e, s) : r ? r.value = s : t.set(e, s), s;
};

const n = 1e3;

class r {
  constructor() {
    this.handlers = new Map, this.nativeTargets = new Set, this.stagedPlanRequest = null, 
    this.stackDepth = new Map, this.traceState = {}, this.nextId = 1, this.started = Date.now(), 
    this.pendingEvents = [], this.flushTimer = null, this.cachedModuleResolver = null, 
    this.cachedObjcResolver = null, this.cachedSwiftResolver = null, this.onTraceError = ({id: e, name: t, message: s}) => {
      send({
        type: "agent:warning",
        id: e,
        message: `Skipping "${t}": ${s}`
      });
    }, this.flush = () => {
      if (null !== this.flushTimer && (clearTimeout(this.flushTimer), this.flushTimer = null), 
      0 === this.pendingEvents.length) return;
      const e = this.pendingEvents;
      this.pendingEvents = [], send({
        type: "events:add",
        events: e
      });
    };
  }
  init(e, t, s, n) {
    const r = global;
    r.stage = e, r.parameters = t, r.state = this.traceState, r.defineHandler = e => e;
    for (const e of s) try {
      (0, eval)(e.source);
    } catch (t) {
      throw new Error(`unable to load ${e.filename}: ${t.stack}`);
    }
    return this.start(n).catch((e => {
      send({
        type: "agent:error",
        message: e.message
      });
    })), {
      id: Process.id,
      platform: Process.platform,
      arch: Process.arch,
      pointer_size: Process.pointerSize,
      page_size: Process.pageSize,
      main_module: Process.mainModule
    };
  }
  dispose() {
    this.flush();
  }
  updateHandlerCode(e, t, s) {
    const n = this.handlers.get(e);
    if (void 0 === n) throw new Error("invalid target ID");
    if (3 === n.length) {
      const r = this.parseFunctionHandler(s, e, t, this.onTraceError);
      n[0] = r[0], n[1] = r[1];
    } else {
      const r = this.parseInstructionHandler(s, e, t, this.onTraceError);
      n[0] = r[0];
    }
  }
  updateHandlerConfig(e, t) {
    const s = this.handlers.get(e);
    if (void 0 === s) throw new Error("invalid target ID");
    s[2] = t;
  }
  async stageTargets(e) {
    const t = await this.createPlan(e);
    this.stagedPlanRequest = t, await t.ready;
    const {plan: s} = t, n = [];
    let r = 1;
    for (const [e, t, a] of s.native.values()) n.push([ r, t, a ]), r++;
    r = -1;
    for (const e of s.java) for (const [t, s] of e.classes.entries()) for (const e of s.methods.values()) n.push([ r, t, e ]), 
    r--;
    return n;
  }
  async commitTargets(e) {
    const t = this.stagedPlanRequest;
    this.stagedPlanRequest = null;
    let {plan: s} = t;
    null !== e && (s = this.cropStagedPlan(s, e));
    const n = [], r = e => {
      n.push(e);
    }, a = await this.traceNativeTargets(s.native, r);
    let o = [];
    return 0 !== s.java.length && (o = await new Promise(((e, t) => {
      Java.perform((() => {
        this.traceJavaTargets(s.java, r).then(e, t);
      }));
    }))), {
      ids: [ ...a, ...o ],
      errors: n
    };
  }
  readMemory(e, t) {
    try {
      return ptr(e).readVolatile(t);
    } catch (e) {
      return null;
    }
  }
  resolveAddresses(e) {
    let t = null;
    return e.map(ptr).map(DebugSymbol.fromAddress).map((e => {
      if (null === e.name) {
        null === t && (t = new ModuleMap);
        const s = t.find(e.address);
        if (null !== s) return `${s.name}!${e.address.sub(s.base)}`;
      }
      return e;
    })).map((e => e.toString()));
  }
  cropStagedPlan(e, t) {
    let s;
    if (t < 0) {
      s = -1;
      for (const n of e.java) for (const [e, r] of n.classes.entries()) for (const [a, o] of r.methods.entries()) {
        if (s === t) {
          const t = {
            methods: new Map([ [ a, o ] ])
          }, s = {
            loader: n.loader,
            classes: new Map([ [ e, t ] ])
          }, r = new b;
          return r.java.push(s), r;
        }
        s--;
      }
    } else {
      s = 1;
      for (const [n, r] of e.native.entries()) {
        if (s === t) {
          const e = new b;
          return e.native.set(n, r), e;
        }
        s++;
      }
    }
    throw new Error("invalid staged item ID");
  }
  async start(e) {
    const t = await this.createPlan(e, (async e => {
      await this.traceJavaTargets(e.java, this.onTraceError);
    }));
    await this.traceNativeTargets(t.plan.native, this.onTraceError), send({
      type: "agent:initialized"
    }), t.ready.then((() => {
      send({
        type: "agent:started",
        count: this.handlers.size
      });
    }));
  }
  async createPlan(e, t = async () => {}) {
    const s = new b, n = [];
    for (const [t, r, a] of e) switch (r) {
     case "module":
      "include" === t ? this.includeModule(a, s) : this.excludeModule(a, s);
      break;

     case "function":
      "include" === t ? this.includeFunction(a, s) : this.excludeFunction(a, s);
      break;

     case "relative-function":
      "include" === t && this.includeRelativeFunction(a, s);
      break;

     case "absolute-instruction":
      "include" === t && this.includeAbsoluteInstruction(ptr(a), s);
      break;

     case "imports":
      "include" === t && this.includeImports(a, s);
      break;

     case "objc-method":
      "include" === t ? this.includeObjCMethod(a, s) : this.excludeObjCMethod(a, s);
      break;

     case "swift-func":
      "include" === t ? this.includeSwiftFunc(a, s) : this.excludeSwiftFunc(a, s);
      break;

     case "java-method":
      n.push([ t, a ]);
      break;

     case "debug-symbol":
      "include" === t && this.includeDebugSymbol(a, s);
    }
    for (const e of s.native.keys()) this.nativeTargets.has(e) && s.native.delete(e);
    let r, a = !0;
    if (n.length > 0) {
      if (!Java.available) throw new Error("Java runtime is not available");
      r = new Promise(((e, r) => {
        Java.perform((async () => {
          a = !1;
          try {
            for (const [e, t] of n) "include" === e ? this.includeJavaMethod(t, s) : this.excludeJavaMethod(t, s);
            await t(s), e();
          } catch (e) {
            r(e);
          }
        }));
      }));
    } else r = Promise.resolve();
    return a || await r, {
      plan: s,
      ready: r
    };
  }
  async traceNativeTargets(e, t) {
    const s = new Map, n = new Map, r = new Map, a = new Map;
    for (const [t, [o, i, c]] of e.entries()) {
      let e;
      switch (o) {
       case "insn":
        e = s;
        break;

       case "c":
        e = n;
        break;

       case "objc":
        e = r;
        break;

       case "swift":
        e = a;
      }
      let l = e.get(i);
      void 0 === l && (l = [], e.set(i, l)), l.push([ c, ptr(t) ]);
    }
    const [o, i, c] = await Promise.all([ this.traceNativeEntries("insn", s, t), this.traceNativeEntries("c", n, t), this.traceNativeEntries("objc", r, t), this.traceNativeEntries("swift", a, t) ]);
    return [ ...o, ...i, ...c ];
  }
  async traceNativeEntries(e, t, s) {
    if (0 === t.size) return [];
    const n = this.nextId, r = [], o = {
      type: "handlers:get",
      flavor: e,
      baseId: n,
      scopes: r
    };
    for (const [e, s] of t.entries()) r.push({
      name: e,
      members: s.map((e => e[0])),
      addresses: s.map((e => e[1].toString()))
    }), this.nextId += s.length;
    const {scripts: i} = await a(o), c = [];
    let l = 0;
    const d = "insn" === e;
    for (const e of t.values()) for (const [t, r] of e) {
      const e = n + l, a = "string" == typeof t ? t : t[1], o = d ? this.parseInstructionHandler(i[l], e, a, s) : this.parseFunctionHandler(i[l], e, a, s);
      this.handlers.set(e, o), this.nativeTargets.add(r.toString());
      try {
        Interceptor.attach(r, d ? this.makeNativeInstructionListener(e, o) : this.makeNativeFunctionListener(e, o));
      } catch (t) {
        s({
          id: e,
          name: a,
          message: t.message
        });
      }
      c.push(e), l++;
    }
    return c;
  }
  async traceJavaTargets(e, t) {
    const s = this.nextId, n = [], r = {
      type: "handlers:get",
      flavor: "java",
      baseId: s,
      scopes: n
    };
    for (const t of e) for (const [e, {methods: s}] of t.classes.entries()) {
      const t = e.split("."), r = t[t.length - 1], a = Array.from(s.keys()).map((e => [ e, `${r}.${e}` ]));
      n.push({
        name: e,
        members: a
      }), this.nextId += a.length;
    }
    const {scripts: o} = await a(r);
    return new Promise((n => {
      Java.perform((() => {
        const r = [];
        let a = 0;
        for (const n of e) {
          const e = Java.ClassFactory.get(n.loader);
          for (const [i, {methods: c}] of n.classes.entries()) {
            const n = e.use(i);
            for (const [e, i] of c.entries()) {
              const c = s + a, l = this.parseFunctionHandler(o[a], c, i, t);
              this.handlers.set(c, l);
              const d = n[e];
              for (const e of d.overloads) e.implementation = this.makeJavaMethodWrapper(c, e, l);
              r.push(c), a++;
            }
          }
        }
        n(r);
      }));
    }));
  }
  makeNativeFunctionListener(e, t) {
    const s = this;
    return {
      onEnter(n) {
        const [r, a, o] = t;
        s.invokeNativeHandler(e, r, o, this, n, ">");
      },
      onLeave(n) {
        const [r, a, o] = t;
        s.invokeNativeHandler(e, a, o, this, n, "<");
      }
    };
  }
  makeNativeInstructionListener(e, t) {
    const s = this;
    return function(n) {
      const [r, a] = t;
      s.invokeNativeHandler(e, r, a, this, n, "|");
    };
  }
  makeJavaMethodWrapper(e, t, s) {
    const n = this;
    return function(...r) {
      return n.handleJavaInvocation(e, t, s, this, r);
    };
  }
  handleJavaInvocation(e, t, s, n, r) {
    const [a, o, i] = s;
    this.invokeJavaHandler(e, a, i, n, r, ">");
    const c = t.apply(n, r), l = this.invokeJavaHandler(e, o, i, n, c, "<");
    return void 0 !== l ? l : c;
  }
  invokeNativeHandler(e, t, s, n, r, a) {
    const o = n.threadId, i = this.updateDepth(o, a);
    if (s.muted) return;
    const c = Date.now() - this.started, l = n.returnAddress.toString(), d = s.capture_backtraces ? Thread.backtrace(n.context).map((e => e.toString())) : null;
    t.call(n, ((...t) => {
      this.emit([ e, c, o, i, l, d, t.join(" ") ]);
    }), r, this.traceState);
  }
  invokeJavaHandler(e, t, s, n, r, a) {
    const o = Process.getCurrentThreadId(), i = this.updateDepth(o, a);
    if (s.muted) return;
    const c = Date.now() - this.started, l = (...t) => {
      this.emit([ e, c, o, i, null, null, t.join(" ") ]);
    };
    try {
      return t.call(n, l, r, this.traceState);
    } catch (e) {
      if (void 0 !== e.$h) throw e;
      Script.nextTick((() => {
        throw e;
      }));
    }
  }
  updateDepth(e, t) {
    const s = this.stackDepth;
    let n = s.get(e) ?? 0;
    return ">" === t ? s.set(e, n + 1) : "<" === t && (n--, 0 !== n ? s.set(e, n) : s.delete(e)), 
    n;
  }
  parseFunctionHandler(e, t, s, n) {
    try {
      const t = this.parseHandlerScript(s, e);
      return [ t.onEnter ?? w, t.onLeave ?? w, o() ];
    } catch (e) {
      return n({
        id: t,
        name: s,
        message: e.message
      }), [ w, w, o() ];
    }
  }
  parseInstructionHandler(e, t, s, n) {
    try {
      return [ this.parseHandlerScript(s, e), o() ];
    } catch (e) {
      return n({
        id: t,
        name: s,
        message: e.message
      }), [ w, o() ];
    }
  }
  parseHandlerScript(e, t) {
    const s = `/handlers/${e}.js`;
    return Script.evaluate(s, t);
  }
  includeModule(e, t) {
    const {native: s} = t;
    for (const t of this.getModuleResolver().enumerateMatches(`exports:${e}!*`)) s.set(t.address.toString(), c(t));
  }
  excludeModule(e, t) {
    const {native: s} = t;
    for (const t of this.getModuleResolver().enumerateMatches(`exports:${e}!*`)) s.delete(t.address.toString());
  }
  includeFunction(e, t) {
    const s = h(e), {native: n} = t;
    for (const e of this.getModuleResolver().enumerateMatches(`exports:${s.module}!${s.function}`)) n.set(e.address.toString(), c(e));
  }
  excludeFunction(e, t) {
    const s = h(e), {native: n} = t;
    for (const e of this.getModuleResolver().enumerateMatches(`exports:${s.module}!${s.function}`)) n.delete(e.address.toString());
  }
  includeRelativeFunction(e, t) {
    const s = f(e), n = Module.getBaseAddress(s.module).add(s.offset);
    t.native.set(n.toString(), [ "c", s.module, `sub_${s.offset.toString(16)}` ]);
  }
  includeAbsoluteInstruction(e, t) {
    const s = t.modules.find(e);
    null !== s ? t.native.set(e.toString(), [ "insn", s.path, `insn_${e.sub(s.base).toString(16)}` ]) : t.native.set(e.toString(), [ "insn", "", `insn_${e.toString(16)}` ]);
  }
  includeImports(e, t) {
    let s;
    if (null === e) {
      const e = Process.enumerateModules()[0].path;
      s = this.getModuleResolver().enumerateMatches(`imports:${e}!*`);
    } else s = this.getModuleResolver().enumerateMatches(`imports:${e}!*`);
    const {native: n} = t;
    for (const e of s) n.set(e.address.toString(), c(e));
  }
  includeObjCMethod(e, t) {
    const {native: s} = t;
    for (const t of this.getObjcResolver().enumerateMatches(e)) s.set(t.address.toString(), l(t));
  }
  excludeObjCMethod(e, t) {
    const {native: s} = t;
    for (const t of this.getObjcResolver().enumerateMatches(e)) s.delete(t.address.toString());
  }
  includeSwiftFunc(e, t) {
    const {native: s} = t;
    for (const t of this.getSwiftResolver().enumerateMatches(`functions:${e}`)) s.set(t.address.toString(), d(t));
  }
  excludeSwiftFunc(e, t) {
    const {native: s} = t;
    for (const t of this.getSwiftResolver().enumerateMatches(`functions:${e}`)) s.delete(t.address.toString());
  }
  includeJavaMethod(e, t) {
    const s = t.java, n = Java.enumerateMethods(e);
    for (const e of n) {
      const {loader: t} = e, n = g(s, (e => {
        const {loader: s} = e;
        return null !== s && null !== t ? s.equals(t) : s === t;
      }));
      if (void 0 === n) {
        s.push(m(e));
        continue;
      }
      const {classes: r} = n;
      for (const t of e.classes) {
        const {name: e} = t, s = r.get(e);
        if (void 0 === s) {
          r.set(e, p(t));
          continue;
        }
        const {methods: n} = s;
        for (const e of t.methods) {
          const t = v(e), s = n.get(t);
          void 0 === s ? n.set(t, e) : n.set(t, e.length > s.length ? e : s);
        }
      }
    }
  }
  excludeJavaMethod(e, t) {
    const s = t.java, n = Java.enumerateMethods(e);
    for (const e of n) {
      const {loader: t} = e, n = g(s, (e => {
        const {loader: s} = e;
        return null !== s && null !== t ? s.equals(t) : s === t;
      }));
      if (void 0 === n) continue;
      const {classes: r} = n;
      for (const t of e.classes) {
        const {name: e} = t, s = r.get(e);
        if (void 0 === s) continue;
        const {methods: n} = s;
        for (const e of t.methods) {
          const t = v(e);
          n.delete(t);
        }
      }
    }
  }
  includeDebugSymbol(e, t) {
    const {native: s} = t;
    for (const t of DebugSymbol.findFunctionsMatching(e)) s.set(t.toString(), u(t));
  }
  emit(e) {
    this.pendingEvents.push(e), null === this.flushTimer && (this.flushTimer = setTimeout(this.flush, 50));
  }
  getModuleResolver() {
    let e = this.cachedModuleResolver;
    return null === e && (e = new ApiResolver("module"), this.cachedModuleResolver = e), 
    e;
  }
  getObjcResolver() {
    let e = this.cachedObjcResolver;
    if (null === e) {
      try {
        e = new ApiResolver("objc");
      } catch (e) {
        throw new Error("Objective-C runtime is not available");
      }
      this.cachedObjcResolver = e;
    }
    return e;
  }
  getSwiftResolver() {
    let e = this.cachedSwiftResolver;
    if (null === e) {
      try {
        e = new ApiResolver("swift");
      } catch (e) {
        throw new Error("Swift runtime is not available");
      }
      this.cachedSwiftResolver = e;
    }
    return e;
  }
}

async function a(e) {
  const t = [], {type: s, flavor: r, baseId: a} = e, o = e.scopes.slice().map((({name: e, members: t, addresses: s}) => ({
    name: e,
    members: t.slice(),
    addresses: s?.slice()
  })));
  let c = a;
  do {
    const e = [], a = {
      type: s,
      flavor: r,
      baseId: c,
      scopes: e
    };
    let l = 0;
    for (const {name: t, members: s, addresses: r} of o) {
      const a = Math.min(s.length, n - l);
      if (0 === a) break;
      e.push({
        name: t,
        members: s.splice(0, a),
        addresses: r?.splice(0, a)
      }), l += a;
    }
    for (;0 !== o.length && 0 === o[0].members.length; ) o.splice(0, 1);
    send(a);
    const d = await i(`reply:${c}`);
    t.push(...d.scripts), c += l;
  } while (0 !== o.length);
  return {
    scripts: t
  };
}

function o() {
  return {
    muted: !1,
    capture_backtraces: !1
  };
}

function i(e) {
  return new Promise((t => {
    recv(e, (e => {
      t(e);
    }));
  }));
}

function c(e) {
  const [t, s] = e.name.split("!").slice(-2);
  return [ "c", t, s ];
}

function l(e) {
  const {name: t} = e, [s, n] = t.substr(2, t.length - 3).split(" ", 2);
  return [ "objc", s, [ n, t ] ];
}

function d(e) {
  const {name: t} = e, [s, n] = t.split("!", 2);
  return [ "swift", s, n ];
}

function u(e) {
  const t = DebugSymbol.fromAddress(e);
  return [ "c", t.moduleName ?? "", t.name ];
}

function h(e) {
  const t = e.split("!", 2);
  let s, n;
  return 1 === t.length ? (s = "*", n = t[0]) : (s = "" === t[0] ? "*" : t[0], n = "" === t[1] ? "*" : t[1]), 
  {
    module: s,
    function: n
  };
}

function f(e) {
  const t = e.split("!", 2);
  return {
    module: t[0],
    offset: parseInt(t[1], 16)
  };
}

function m(e) {
  return {
    loader: e.loader,
    classes: new Map(e.classes.map((e => [ e.name, p(e) ])))
  };
}

function p(e) {
  return {
    methods: new Map(e.methods.map((e => [ v(e), e ])))
  };
}

function v(e) {
  const t = e.indexOf("(");
  return -1 === t ? e : e.substr(0, t);
}

function g(e, t) {
  for (const s of e) if (t(s)) return s;
}

function w() {}

class b {
  constructor() {
    this.native = new Map, this.java = [], e.set(this, null);
  }
  get modules() {
    let n = t(this, e, "f");
    return null === n && (n = new ModuleMap, s(this, e, n, "f")), n;
  }
}

e = new WeakMap;

const M = new r;

rpc.exports = {
  init: M.init.bind(M),
  dispose: M.dispose.bind(M),
  updateHandlerCode: M.updateHandlerCode.bind(M),
  updateHandlerConfig: M.updateHandlerConfig.bind(M),
  stageTargets: M.stageTargets.bind(M),
  commitTargets: M.commitTargets.bind(M),
  readMemory: M.readMemory.bind(M),
  resolveAddresses: M.resolveAddresses.bind(M)
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7Ozs7Ozs7Ozs7O0FDQUEsTUFBTSxJQUEyQjs7QUFFakMsTUFBTTtFQUFOLFdBQUE7SUFDWSxLQUFBLFdBQVcsSUFBSSxLQUNmLEtBQUEsZ0JBQWdCLElBQUksS0FDcEIsS0FBQSxvQkFBNkM7SUFDN0MsS0FBQSxhQUFhLElBQUksS0FDakIsS0FBQSxhQUF5QixJQUN6QixLQUFBLFNBQVMsR0FDVCxLQUFBLFVBQVUsS0FBSztJQUVmLEtBQUEsZ0JBQThCLElBQzlCLEtBQUEsYUFBa0IsTUFFbEIsS0FBQSx1QkFBMkM7SUFDM0MsS0FBQSxxQkFBeUMsTUFDekMsS0FBQSxzQkFBMEMsTUEwTTFDLEtBQUEsZUFBdUMsRUFBRyxPQUFJLFNBQU07TUFDeEQsS0FBSztRQUNELE1BQU07UUFDTjtRQUNBLFNBQVMsYUFBYSxPQUFVOztBQUNsQyxPQW9rQkUsS0FBQSxRQUFRO01BTVosSUFMd0IsU0FBcEIsS0FBSyxlQUNMLGFBQWEsS0FBSyxhQUNsQixLQUFLLGFBQWE7TUFHWSxNQUE5QixLQUFLLGNBQWMsUUFDbkI7TUFHSixNQUFNLElBQVMsS0FBSztNQUNwQixLQUFLLGdCQUFnQixJQUVyQixLQUFLO1FBQ0QsTUFBTTtRQUNOOztBQUNGO0FBcUNWO0VBdDBCSSxJQUFBLENBQUssR0FBYyxHQUE2QixHQUEyQjtJQUN2RSxNQUFNLElBQUk7SUFDVixFQUFFLFFBQVEsR0FDVixFQUFFLGFBQWEsR0FDZixFQUFFLFFBQVEsS0FBSyxZQUNmLEVBQUUsZ0JBQWdCLEtBQUs7SUFFdkIsS0FBSyxNQUFNLEtBQVUsR0FDakI7T0FDSSxHQUFJLE1BQU0sRUFBTztNQUNuQixPQUFPO01BQ0wsTUFBTSxJQUFJLE1BQU0sa0JBQWtCLEVBQU8sYUFBYSxFQUFFOztJQVdoRSxPQVBBLEtBQUssTUFBTSxHQUFNLE9BQU07TUFDbkIsS0FB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
```