Response:
Let's break down the thought process for analyzing this Frida script.

**1. Initial Understanding of the Context:**

The first sentence is crucial: "这是目录为frida/subprojects/frida-core/src/darwin/agent/reportcrash.js的fridaDynamic instrumentation tool的源代码文件". This tells us:

* **Frida:**  It's a Frida script, meaning its purpose is dynamic instrumentation (modifying a running process's behavior).
* **Path:**  `frida/subprojects/frida-core/src/darwin/agent/reportcrash.js`  This is the key. `darwin` signifies macOS/iOS. `agent` suggests it runs within the target process. `reportcrash` strongly hints at its involvement in crash reporting.

**2. High-Level Goal Identification:**

Given the name `reportcrash.js` and the context of Frida, the core functionality is likely to intercept and modify the crash reporting process on macOS/iOS. It's not *generating* crashes, but rather *interacting* with the system's existing crash reporting mechanism.

**3. Deconstructing the Code - Keyword and API Analysis:**

Start looking for key Frida APIs and concepts:

* **`Interceptor.attach(...)`:** This is the heart of Frida. It means the script is hooking into existing functions. Each `Interceptor.attach` block needs to be analyzed individually to understand *what* is being hooked and *why*.
* **`Module.getExportByName(...)`:**  This indicates interaction with system libraries (`libsystem_kernel.dylib`, `CoreSymbolication`, `CrashReporterSupport`). It points towards low-level operations.
* **`ObjC.classes...`:**  This clearly shows interaction with Objective-C runtime. The classes listed (`AppleErrorReport`, `CrashReport`, `NSMutableDictionary`, etc.) are all part of the macOS/iOS frameworks related to crash reporting.
* **`NativeFunction`:** This confirms calls into native (C/C++) functions.
* **`send(...)` and `recv(...)`:** These are Frida's communication channels between the agent (running in the target) and the host (where the Frida script is controlled from). This implies data exchange about crashes.
* **`Memory.*`:** Direct memory manipulation, indicating low-level interactions and data extraction.

**4. Analyzing Individual `Interceptor.attach` Blocks (Iterative Process):**

Go through each `Interceptor.attach` call and ask:

* **What function is being hooked?**  Look at the `Module.getExportByName` or Objective-C method name.
* **When does the hook trigger (`onEnter`, `onLeave`)?**
* **What are the arguments (`args`)?** What data is available at this point?
* **What is being done in the hook?** Look for modifications to arguments, return values, or actions taken using other Frida APIs.
* **Why is this being done?**  Infer the purpose based on the function being hooked and the actions taken.

**Example of Analyzing an `Interceptor.attach` Block:**

```javascript
Interceptor.attach(CrashReportImpl['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, {
  onEnter(args) {
    const task = args[2].toUInt32();
    const crashedPid = pidForTask(task);

    const session = createSession(this.threadId, crashedPid);

    send(['crash-detected', crashedPid]);
    const op = recv('mapped-agents', message => {
      session.mappedAgents = message.payload.map(agent => {
        return {
          machHeaderAddress: uint64(agent.machHeaderAddress),
          uuid: agent.uuid,
          path: agent.path,
        };
      });
    });
    op.wait();
  }
});
```

* **What:**  Hooking the `initWithTask:exceptionType:...` method of `CrashReportImpl`. This is likely the initialization of a crash report object.
* **When:** `onEnter`. Actions happen *before* the original method executes.
* **Args:** The arguments likely contain information about the crashing process. `args[2]` is identified as the task port.
* **Doing:**
    * Extracts the task and gets the PID using `pidForTask`.
    * Creates a `session` to track information related to this crash.
    * Sends a `crash-detected` message to the host.
    * Receives `mapped-agents` information from the host and stores it in the session. This strongly suggests gathering information about loaded libraries/agents in the crashed process.
* **Why:** To intercept the creation of a crash report, notify the host, and gather additional information about loaded agents.

**5. Identifying Key Functionalities and Relationships:**

After analyzing several `Interceptor.attach` blocks, patterns emerge:

* **Crash Detection and Session Management:**  Creating and managing sessions for each crash.
* **Forcing Actionability:**  Overriding the system's decision on whether to generate a crash report.
* **Log Handling:** Intercepting log file creation, modification, and reading.
* **Symbolication Assistance:**  Gathering information about loaded libraries (mapped agents) to help with symbolication.
* **Bypassing Limits:**  Overriding limits on logging.
* **Dealing with Dynamic Libraries (dyld):**  Hooking into `libdyld` to potentially inject information about Frida's own injected code.
* **Stack Frame Fixup:**  Attempting to correct stack frames, possibly related to Frida's own intervention.

**6. Answering the Specific Questions:**

With a good understanding of the code's functionality, address each question systematically:

* **功能 (Functions):** Summarize the identified functionalities in clear bullet points.
* **与逆向的关系 (Relationship with Reverse Engineering):** Explain how the script's actions (e.g., forcing crash reports, gathering library information) are beneficial for reverse engineers. Provide concrete examples.
* **涉及的底层知识 (Low-Level Knowledge):** Point out the use of kernel functions, Objective-C runtime, memory manipulation, and how these relate to operating system internals.
* **逻辑推理 (Logical Reasoning):** Identify scenarios where the script makes decisions or manipulates data based on certain conditions. Provide hypothetical inputs and outputs.
* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Think about how a user interacting with this script (through Frida's host API) might make mistakes or how the script itself could have errors (though this script is well-written, consider general Frida pitfalls).
* **用户操作步骤 (User Operation Steps):** Describe the typical Frida workflow that would lead to this script being executed.

**7. Refinement and Organization:**

Review the analysis for clarity, accuracy, and completeness. Organize the information logically to address each part of the prompt effectively. Use clear language and avoid overly technical jargon where possible.

This iterative process of understanding the context, deconstructing the code, identifying functionalities, and then relating those functionalities to the specific questions is key to analyzing Frida scripts effectively. The focus on Frida's core concepts and the target platform's (macOS/iOS) specific APIs is crucial.
这个Frida脚本 `reportcrash.js` 的主要功能是 **增强和控制 iOS/macOS 上的崩溃报告机制，以便在 Frida 进行动态插桩时捕获更详细的崩溃信息，并允许用户强制生成崩溃报告。**

下面是它的具体功能以及与你提出的问题的关联：

**1. 功能列举:**

* **拦截崩溃报告的创建:**  Hook `CrashReport` 或 `LegacyCrashReport` 类的初始化方法 (`- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:`)，以便在崩溃发生时获得通知。
* **获取崩溃进程的 PID:**  通过 `pid_for_task` 系统调用获取发生崩溃的进程的进程 ID。
* **与 Frida Host 通信:**  使用 `send` 函数向 Frida Host 发送 `crash-detected` 消息，告知 Host 发生了崩溃。
* **接收映射的 Agent 信息:**  通过 `recv` 函数接收来自 Frida Host 的 `mapped-agents` 消息，该消息包含当前已加载到崩溃进程中的 Frida Agent 的信息，例如 Mach-O 文件的地址、UUID 和路径。这对于后续的符号化非常重要。
* **强制生成崩溃报告:**  Hook `CrashReport` 的 `- isActionable` 方法，并始终返回 `YES`，即使系统认为该崩溃不值得生成报告。这允许 Frida 用户在需要时强制生成崩溃报告。
* **绕过日志限制:**  Hook `NSMutableDictionary` 的日志方法 (例如 `- osa_logCounter_isLog:byKey:count:withinLimit:withOptions:` 或 `- logCounter_isLog:byKey:count:withinLimit:withOptions:`)，并始终返回 `YES`，以确保所有相关的日志信息都被包含在崩溃报告中。
* **捕获崩溃日志内容:**
    * 对于较新的 iOS 版本，Hook `OSALog` 的 `+ createForSubmission:metadata:options:error:writing:` 方法，读取生成的崩溃日志文件的内容。
    * 对于较老的 iOS 版本，Hook `rename`、`open_dprotected_np` 和 `write` 系统调用，监控崩溃日志文件的创建和写入过程，并收集日志内容。
* **删除强制生成的崩溃报告:**  Hook `OSAReport` 或 `AppleErrorReport` 的保存方法 (`- saveWithOptions:` 或 `- saveToDir:`)，如果该报告是 Frida 强制生成的，则删除该文件。
* **禁用符号化偏好:**  Hook `OSAPreferencesGetBoolValue` 函数，并拦截对 `SymbolicateCrashes` 偏好的查询，始终返回 `YES`，确保崩溃报告包含符号信息。
* **处理 dyld 信息:**  Hook `libdyld.dylib` 中的函数，例如 `dyld_process_info_base::make` 和 `withRemoteBuffer`，以便在崩溃报告中包含 Frida Agent 的加载信息。这对于 Frida Agent 自身的调试非常重要。
* **修复采样堆栈帧:**  对于 arm64 架构，Hook `VMUSampler` 和 `VMUBacktrace` 相关方法，尝试修复由于 Frida 的插桩而可能导致的堆栈帧错误。
* **识别 CrashReport 类:**  动态查找 `CrashReport` 或 `LegacyCrashReport` 类，以兼容不同的 iOS 版本。

**2. 与逆向方法的关系:**

这个脚本与逆向方法紧密相关，因为它增强了逆向工程人员使用 Frida 进行动态插桩时获取崩溃信息的能力。

* **示例说明:**  假设逆向工程师在使用 Frida 分析一个应用程序，并触发了一个崩溃。默认情况下，iOS/macOS 可能不会生成崩溃报告，或者生成的报告可能不包含 Frida Agent 的信息。通过运行这个脚本，逆向工程师可以：
    * **强制生成崩溃报告:** 即使系统认为不需要生成，也能获得崩溃时的详细信息。
    * **获取包含 Frida Agent 信息的崩溃报告:**  脚本会修改 `libdyld` 的行为，确保崩溃报告中包含 Frida Agent 的加载地址、UUID 和路径，这对于分析 Frida Agent 的行为至关重要。
    * **获取更完整的日志信息:**  绕过日志限制，确保与崩溃相关的更详细的日志信息被记录下来，帮助理解崩溃原因。
    * **修复可能错误的堆栈信息:**  尝试修复由于 Frida 插桩导致的堆栈帧错误，提高崩溃报告的准确性，方便回溯崩溃时的调用栈。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识:**

虽然这个脚本是针对 Darwin (macOS/iOS) 平台的，但其原理涉及一些通用的底层概念：

* **二进制底层:**
    * **Mach-O 文件格式:**  脚本中获取 Agent 的 `machHeaderAddress` 和 `uuid`，这些都是 Mach-O 文件头中的信息。
    * **内存地址:**  脚本中大量操作内存地址，例如读取和写入内存数据。
    * **函数调用约定:**  Frida 的 `Interceptor.attach` 和 `NativeFunction` 的工作原理依赖于理解目标平台的函数调用约定。
* **Linux 内核知识 (部分通用性):**
    * **进程和线程:**  脚本中使用了 `pid_for_task` 来获取进程 ID，以及通过 `this.threadId` 来区分不同的线程。虽然 `task` 是 macOS 特有的概念，但进程和线程是操作系统通用的概念。
    * **系统调用:**  脚本中使用了 `unlink`、`rename`、`open_dprotected_np` 和 `write` 等系统调用。
* **Android 内核及框架知识 (相对较少，但原理有共通之处):**
    * 虽然这个脚本是针对 Darwin 的，但动态插桩的理念和方法在 Android 上也有应用。例如，Android 的崩溃报告机制也有类似的结构，可以通过 Hook 技术进行修改。

**4. 逻辑推理 (假设输入与输出):**

假设 Frida Host 发送以下 `mapped-agents` 信息：

```json
[
  {
    "machHeaderAddress": "0x100000000",
    "uuid": "E7B18E0A-1B2C-3D4E-9F5A-6B7C8D9E0A1B",
    "path": "/path/to/my_agent.dylib"
  }
]
```

**输入:**

* 一个应用程序发生崩溃。
* Frida Agent 已经注入到该应用程序中。
* Frida Host 发送上述 `mapped-agents` 信息。

**输出:**

* 脚本会创建一个包含以下信息的 `session` 对象：
    * `crashedPid`: 崩溃进程的 PID。
    * `mappedAgents`: 包含 Agent 的 `machHeaderAddress` (0x100000000)、`uuid` ("E7B18E0A-1B2C-3D4E-9F5A-6B7C8D9E0A1B") 和 `path` ("/path/to/my_agent.dylib") 的数组。
* 如果是强制生成的崩溃报告，崩溃报告的内容很可能会包含有关 `/path/to/my_agent.dylib` 的信息，例如其加载地址。

**5. 用户或编程常见的使用错误:**

* **Frida Host 未发送 `mapped-agents` 信息:** 如果 Frida Host 没有正确地向 Agent 发送 `mapped-agents` 信息，那么崩溃报告可能不会包含 Frida Agent 的加载信息。这可能是由于 Frida Host 脚本的错误或者 Frida 版本不兼容导致的。
* **权限问题:**  Frida 需要足够的权限才能 Hook 系统调用和访问进程内存。如果 Frida 没有相应的权限，脚本可能无法正常工作。
* **目标进程的保护机制:**  某些应用程序可能会使用反调试或代码混淆等技术，使得 Frida 难以 Hook 其函数或访问其内存。
* **Frida 版本不兼容:**  随着 iOS/macOS 版本的更新，系统库的结构和函数签名可能会发生变化。如果 Frida 或该脚本的版本与目标系统不兼容，可能会导致 Hook 失败或程序崩溃。
* **误解强制生成崩溃报告的影响:**  频繁强制生成崩溃报告可能会影响系统性能，并占用磁盘空间。用户应该仅在需要时才使用此功能。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写并运行一个 Frida Host 脚本:**  该脚本使用 Frida API 连接到目标 iOS/macOS 应用程序。
2. **Frida Host 脚本加载 `reportcrash.js` Agent 脚本到目标进程:**  通常通过 `session.inject()` 或在 Host 脚本中使用 `frida-compile` 将 Agent 代码打包并注入。
3. **Frida Agent 脚本 `reportcrash.js` 被注入到目标进程中并开始执行 `initialize()` 函数。**
4. **`initialize()` 函数 Hook 了 `CRCreateDirectoryStructure` 函数。**
5. **当目标进程因为某些原因崩溃时，iOS/macOS 的崩溃报告机制开始工作。**
6. **由于 `reportcrash.js` 已经 Hook 了相关的函数，因此脚本的 `Interceptor.attach` 中的 `onEnter` 或 `onLeave` 回调函数会被执行。**
7. **例如，当 `CrashReport` 的初始化方法被调用时，`onEnter` 回调会获取崩溃进程的 PID，并向 Frida Host 发送 `crash-detected` 消息。**
8. **Frida Host 接收到 `crash-detected` 消息后，可能会执行一些操作，例如收集当前已加载的 Agent 信息，并通过 `send` 函数发送 `mapped-agents` 消息回 Agent。**
9. **Agent 接收到 `mapped-agents` 消息后，会将其存储在 `session` 对象中。**
10. **后续的 Hook (例如 `- isActionable`) 会根据 `session` 中的信息或其他条件来修改崩溃报告的行为。**

通过分析这个脚本，逆向工程师可以更好地理解 Frida 如何与 iOS/macOS 的底层机制交互，以及如何利用 Frida 来增强崩溃分析能力。这对于调试 Frida Agent 本身以及分析目标应用程序的崩溃都非常有帮助。

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/darwin/agent/reportcrash.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
const LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
const CORESYMBOLICATION_PATH = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication';
const CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
const YES = ptr(1);

const CSTypeRef = ['pointer', 'pointer'];
const kCSNow = uint64('0x8000000000000000');
const NSUTF8StringEncoding = 4;

const { pointerSize } = Process;

const simpleFuncOptions = {
  scheduling: 'exclusive',
  exceptions: 'propagate'
};
const complexFuncOptions = {
  scheduling: 'cooperative',
  exceptions: 'propagate'
};
const _pidForTask = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer'],
    simpleFuncOptions
);
const unlink = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'unlink'),
    'int',
    ['pointer'],
    simpleFuncOptions
);
const CSSymbolicatorGetSymbolWithAddressAtTime = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSSymbolicatorGetSymbolWithAddressAtTime'),
    CSTypeRef,
    [CSTypeRef, 'uint64', 'uint64'],
    complexFuncOptions
);
const CSIsNull = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSIsNull'),
    'int',
    [CSTypeRef],
    simpleFuncOptions
);
const mappedMemoryRead = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read'),
    'uint',
    ['pointer', 'uint64', 'uint64', 'pointer'],
    simpleFuncOptions
);
const mappedMemoryReadPointer = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read_pointer'),
    'uint',
    ['pointer', 'uint64', 'pointer'],
    simpleFuncOptions
);

const {
  AppleErrorReport,
  CrashReport,
  NSMutableDictionary,
  NSString,
  OSALog,
  OSAReport,
} = ObjC.classes;

const sessions = new Map();
let osaHookState = 'pending';

function initialize() {
  const listener = Interceptor.attach(Module.getExportByName(CRASH_REPORTER_SUPPORT_PATH, 'CRCreateDirectoryStructure'), () => {
    applyInstrumentation();
    listener.detach();
  });
}

function createSession(threadId, crashedPid) {
  const session = {
    crashedPid,
    is64Bit: null,
    forcedByUs: false,
    logPath: null,
    logFd: null,
    logChunks: [],
    mappedAgents: []
  };

  sessions.set(threadId, session);

  return session;
}

function terminateSession(threadId) {
  const session = getSession(threadId, 'terminateSession');

  send(['crash-received', session.crashedPid, session.logChunks.join('')]);

  sessions.delete(threadId);
}

function getSession(threadId, operation) {
  const session = sessions.get(threadId);
  if (session === undefined) {
    throw new Error(`${operation}: missing session for thread ${threadId}`);
  }
  return session;
}

function findSession(threadId) {
  return sessions.get(threadId) ?? null;
}

function applyInstrumentation() {
  const CrashReportImpl = findCrashReportClass() ?? CrashReport;

  Interceptor.attach(CrashReportImpl['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, {
    onEnter(args) {
      const task = args[2].toUInt32();
      const crashedPid = pidForTask(task);

      const session = createSession(this.threadId, crashedPid);

      send(['crash-detected', crashedPid]);
      const op = recv('mapped-agents', message => {
        session.mappedAgents = message.payload.map(agent => {
          return {
            machHeaderAddress: uint64(agent.machHeaderAddress),
            uuid: agent.uuid,
            path: agent.path,
          };
        });
      });
      op.wait();
    }
  });

  Interceptor.attach(CrashReportImpl['- isActionable'].implementation, {
    onLeave(retval) {
      const isActionable = !!retval.toInt32();
      const session = getSession(this.threadId, 'isActionable');
      if (!isActionable) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  Interceptor.attach(Module.getExportByName(CORESYMBOLICATION_PATH, 'task_is_64bit'), {
    onEnter(args) {
      this.pid = pidForTask(args[0].toUInt32());
    },
    onLeave(retval) {
      const session = findSession(this.threadId);
      if (this.pid === session?.crashedPid)
        session.is64Bit = !!retval.toUInt32();
    }
  });

  Interceptor.attach(CrashReportImpl['- isActionable'].implementation, {
    onLeave(retval) {
      const isActionable = !!retval.toInt32();
      const session = getSession(this.threadId, 'isActionable');
      if (!isActionable) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  const methodName = (OSAReport !== undefined)
      ? '- osa_logCounter_isLog:byKey:count:withinLimit:withOptions:'
      : '- logCounter_isLog:byKey:count:withinLimit:withOptions:';
  Interceptor.attach(NSMutableDictionary[methodName].implementation, {
    onLeave(retval) {
      const isWithinLimit = !!retval.toInt32();
      const session = getSession(this.threadId, 'isWithinLimit');
      if (!isWithinLimit) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  const saveImpl = (OSAReport !== undefined)
      ? OSAReport['- saveWithOptions:'].implementation
      : AppleErrorReport['- saveToDir:'].implementation;
  Interceptor.attach(saveImpl, {
    onLeave(retval) {
      const session = findSession(this.threadId);
      if (session === null)
        return;

      if (session.forcedByUs)
        unlink(Memory.allocUtf8String(session.logPath));

      terminateSession(this.threadId);
    },
  });

  const createForSubmission = OSALog?.['+ createForSubmission:metadata:options:error:writing:'];
  if (createForSubmission !== undefined) {
    Interceptor.attach(createForSubmission.implementation, {
      onLeave(retval) {
        const session = findSession(this.threadId);
        if (session === null)
          return;

        const log = new ObjC.Object(retval);
        const filePath = log.filepath();
        const logPath = filePath.toString();
        session.logPath = logPath;

        if (logPath.includes('.forced-by-frida'))
          session.forcedByUs = true;

        session.logChunks.push(NSString.stringWithContentsOfFile_encoding_error_(filePath, NSUTF8StringEncoding, NULL).toString());
      }
    });
  } else {
    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'rename'), {
      onEnter(args) {
        const newPath = args[1].readUtf8String();
        const session = getSession(this.threadId, 'rename');
        if (/\.ips$/.test(newPath))
          session.logPath = newPath;
      },
    });

    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'open_dprotected_np'), {
      onEnter(args) {
        const path = args[0].readUtf8String();
        this.isCrashLog = /\.ips$/.test(path);
      },
      onLeave(retval) {
        const session = getSession(this.threadId, 'open_dprotected_np');
        if (this.isCrashLog)
          session.logFd = retval.toInt32();
      },
    });

    Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
      onEnter(args) {
        const fd = args[0].toInt32();
        this.buf = args[1];

        const session = findSession(this.threadId);
        if (session !== null) {
          this.session = session;
          this.isCrashLog = (fd === session.logFd);
        } else {
          this.isCrashLog = false;
        }
      },
      onLeave(retval) {
        if (!this.isCrashLog)
          return;

        const n = retval.toInt32();
        if (n === -1)
          return;

        const chunk = this.buf.readUtf8String(n);
        const { session } = this;
        if (session !== undefined)
          session.logChunks.push(chunk);
      }
    });
  }

  Interceptor.attach(Module.getExportByName(CRASH_REPORTER_SUPPORT_PATH, 'OSAPreferencesGetBoolValue'), {
    onEnter(args) {
      this.name = new ObjC.Object(args[0]).toString();
      this.domain = new ObjC.Object(args[1]).toString();
      this.successPtr = args[2];
    },
    onLeave(retval) {
      if (this.name === 'SymbolicateCrashes' && this.domain === 'com.apple.CrashReporter') {
        if (!this.successPtr.isNull())
          this.successPtr.writeU8(1);
        retval.replace(YES);
      }
    }
  });

  const libdyld = findLibdyldInternals();
  if (libdyld !== null) {
    const allImageInfoSizes = new Map([
      [15, 304],
      [16, 328],
      [17, 368],
    ]);
    const imageElementSize = 3 * pointerSize;

    const procInfoInvocations = new Map();

    Interceptor.attach(libdyld['dyld_process_info_base::make'].implementation, {
      onEnter(args) {
        const session = findSession(this.threadId);
        if (session === null)
          return;

        const pid = pidForTask(args[0].toUInt32());
        const allImageInfo = args[1];

        const version = allImageInfo.readU32();
        const count = allImageInfo.add(4).readU32();
        const array = allImageInfo.add(8).readU64();

        const size = allImageInfoSizes.get(version);
        if (size === undefined) {
          console.error('Unsupported dyld_all_image_infos_64; please add support for version ' + version);
          return;
        }

        const extraCount = session.mappedAgents.length;
        const copy = Memory.dup(allImageInfo, size);
        copy.add(4).writeU32(count + extraCount);
        this.allImageInfo = copy;
        args[1] = copy;

        const realSize = count * imageElementSize;
        const fakeSize = realSize + (extraCount * imageElementSize);

        const paths = new Map();

        procInfoInvocations.set(this.threadId, {
          session,
          array,
          realSize,
          fakeSize,
          paths
        });
      },
      onLeave(retval) {
        procInfoInvocations.delete(this.threadId);
      }
    });

    const { withRemoteBuffer } = libdyld;
    const blockArgIndex = withRemoteBuffer.arity - 1;
    Interceptor.attach(withRemoteBuffer.implementation, {
      onEnter(args) {
        const invocation = procInfoInvocations.get(this.threadId);
        if (invocation === undefined)
          return;

        const { session } = invocation;

        const remoteAddress = uint64(args[1].toString());

        if (remoteAddress.equals(invocation.array)) {
          const realSize = invocation.realSize;

          args[2] = ptr(realSize);

          this.block = wrapBlock(args[blockArgIndex], (impl, buffer, size) => {
            const copy = Memory.alloc(invocation.fakeSize);
            Memory.copy(copy, buffer, realSize);

            let element = copy.add(realSize);
            const paths = invocation.paths;
            for (const agent of session.mappedAgents) {
              const loadAddress = agent.machHeaderAddress;
              const filePath = loadAddress.sub(4096);
              const modDate = 0;

              if (session.is64Bit) {
                element
                    .writeU64(loadAddress).add(8)
                    .writeU64(filePath).add(8)
                    .writeU64(modDate);
              } else {
                element
                    .writeU32(loadAddress).add(4)
                    .writeU32(filePath).add(4)
                    .writeU32(modDate);
              }

              paths.set(filePath.toString(), agent);

              element = element.add(imageElementSize);
            }

            return impl(copy, size);
          });

          return;
        }

        const agent = invocation.paths.get(remoteAddress.toString());
        if (agent !== undefined) {
          this.block = wrapBlock(args[blockArgIndex], (impl, buffer, size) => {
            const copy = Memory.dup(buffer, size);
            copy.writeUtf8String(agent.path);
            return impl(copy, size);
          });
        }
      }
    });
  }

  if (Process.arch === 'arm64') {
    Interceptor.attach(ObjC.classes.VMUSampler['- sampleAllThreadsOnceWithFramePointers:'].implementation, {
      onEnter(args) {
        args[2] = YES;
      }
    });

    Interceptor.attach(ObjC.classes.VMUBacktrace['- fixupStackWithSamplingContext:symbolicator:'].implementation, {
      onEnter(args) {
        this.self = new ObjC.Object(args[0]);
        this.samplingContext = args[2];
        this.symbolicator = [args[3], args[4]];
      },
      onLeave() {
        const session = getSession(this.threadId, 'fixupStackWithSamplingContext');
        if (!session.is64Bit)
          return;

        const { self, samplingContext, symbolicator } = this;

        const [, frames, framePtrs, length] = self.$ivars._callstack;
        const mappedMemory = new MappedMemory(samplingContext.add(8).readPointer());

        for (let i = 0; i !== length; i++) {
          const frameSlot = frames.add(i * 8);
          const frame = frameSlot.readU64();

          const symbol = CSSymbolicatorGetSymbolWithAddressAtTime(symbolicator, frame, kCSNow);
          if (!CSIsNull(symbol))
            continue;

          const framePtrAbove = (i > 0) ? framePtrs.add((i - 1) * 8).readU64() : null;

          const functionAddress = tryParseInterceptorTrampoline(frame, framePtrAbove, mappedMemory);
          if (functionAddress !== null)
            frameSlot.writeU64(functionAddress);
        }
      },
    });
  }
}

function findCrashReportClass() {
  const { api } = ObjC;

  const reporter = Process.enumerateModules()[0];
  const reporterStart = reporter.base;
  const reporterEnd = reporterStart.add(reporter.size);

  const numClasses = api.objc_getClassList(NULL, 0);
  const classHandles = Memory.alloc(numClasses * pointerSize);
  api.objc_getClassList(classHandles, numClasses);

  const classGetName = api.class_getName;

  for (let i = numClasses - 1; i >= 0; i--) {
    const classHandle = classHandles.add(i * pointerSize).readPointer();
    const rawName = classGetName(classHandle);
    if (rawName.compare(reporterStart) >= 0 && rawName.compare(reporterEnd) < 0) {
      const name = rawName.readUtf8String();
      if (name === 'LegacyCrashReport' || name === 'CrashReport')
        return new ObjC.Object(classHandle);
    }
  }

  return null;
}

function findLibdyldInternals() {
  if (Process.arch !== 'arm64')
    return null;

  const { base, size } = Process.getModuleByName('/usr/lib/system/libdyld.dylib');

  /*
   * Verified on:
   * - 12.4
   * - 13.2.2
   * - 13.3
   * - 13.5
   * - 14.0
   * - 14.7.1
   */
  const signatures = {
    'dyld_process_info_base::make': [
      [
        // make(unsigned int, dyld_all_image_infos_64 const &, unsigned long long, int *)
        '28 e0 02 91', // add x8, x1, 0xb8
        { arity: 4 }
      ],
    ],
    'withRemoteBuffer': [
      [
        // New: withRemoteBuffer(unsigned int, unsigned long long, unsigned long, bool, int *, void (void *, unsigned long) block_pointer)
        '9f 00 00 f1 ?? ?? ?? ?? 15 00 84 9a : ff ff ff ff ff ff ff ff 1f fc ff ff', // cmp x4, 0; <any instruction>; csel x21, $reg, x4, eq
        { arity: 6 }
      ],
      [
        // Old: withRemoteBuffer(unsigned int, unsigned long long, unsigned long, bool, bool, int *, void (void *, unsigned long) block_pointer)
        'bf 00 00 f1 ?? ?? ?? ?? 14 00 85 9a : ff ff ff ff ff ff ff ff 1f fc ff ff', // cmp x5, 0; <any instruction>; csel x20, $reg, x5, eq
        { arity: 7 }
      ],
    ],
  };

  let prologPattern;
  const isArm64e = !ptr(1).sign().equals(1);
  if (isArm64e) {
    const pacibsp = '7f 23 03 d5';
    prologPattern = pacibsp;
  } else {
    const subSpSpImm = 'ff 03 00 d1 : ff 03 e0 ff';
    prologPattern = subSpSpImm;
  }

  const result = {};
  const missing = [];
  for (const [name, candidates] of Object.entries(signatures)) {
    let found = false;

    for (const [pattern, details] of candidates) {
      const matches = Memory.scanSync(base, size, pattern);
      if (matches.length !== 1)
        continue;
      const match = matches[0].address;

      const prologs = Memory.scanSync(match.sub(256), 256, prologPattern);
      if (prologs.length === 0)
        continue;

      result[name] = Object.assign({ implementation: prologs[prologs.length - 1].address }, details);

      found = true;
      break;
    }

    if (!found)
      missing.push(name);
  }

  if (missing.length !== 0) {
    console.error(`Unsupported version of libdyld.dylib; missing:\n\t${missing.join('\n\t')}`);
    return null;
  }

  return result;
}

function pidForTask(task) {
  const pidBuf = Memory.alloc(4);
  _pidForTask(task, pidBuf);
  return pidBuf.readU32();
}

const pointerBuf = Memory.alloc(8);

class MappedMemory {
  constructor(handle) {
    this.handle = handle;
  }

  read(address, size) {
    const kr = mappedMemoryRead(this.handle, address, size, pointerBuf);
    if (kr !== 0)
      throw new Error('Invalid address: 0x' + address.toString(16));
    return pointerBuf.readPointer().readByteArray(size);
  }

  readPointer(address) {
    const kr = mappedMemoryReadPointer(this.handle, address, pointerBuf);
    if (kr !== 0)
      throw new Error('Invalid address: 0x' + address.toString(16));
    return pointerBuf.readU64();
  }
}

function tryParseInterceptorTrampoline(code, stackFrameAbove, mappedMemory) {
  let instructions;
  try {
    instructions = new Uint32Array(mappedMemory.read(code, 16));
  } catch (e) {
    return null;
  }

  const result = tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory);
  if (result !== null)
    return result;

  return tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory);
}

function tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory) {
  let ldr;

  ldr = tryParseLdrRegAddress(instructions[0], code);
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x17')
    return null;
  const functionContextDPtr = ldr[1];

  ldr = tryParseLdrRegAddress(instructions[1], code.add(4));
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x16')
    return null;

  const isBrX16 = ((instructions[2] & 0xfffff7e0) >>> 0) === 0xd61f0200;
  if (!isBrX16)
    return null;

  return tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory);
}

const interceptorCallbackTrampolineSignature = [
  0x910043ff, // add sp, sp, 0x10
  0xa8c103e1, // ldp x1, x0, [sp], 0x10
  0xa8c10be1, // ldp x1, x2, [sp], 0x10
  0xa8c113e3, // ldp x3, x4, [sp], 0x10
];

function tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory) {
  if (stackFrameAbove === null)
    return null;

  const matches = interceptorCallbackTrampolineSignature.every((insn, index) => instructions[index] === insn);
  if (!matches)
    return null;

  const cpuContextStart = stackFrameAbove.add(16 + 8);
  const x17Start = cpuContextStart.add(19 * 8);
  return tryReadInterceptorFunctionContextDoublePointer(x17Start, mappedMemory);
}

function tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory) {
  try {
    const functionContext = mappedMemory.readPointer(functionContextDPtr);
    const functionAddress = mappedMemory.readPointer(functionContext);
    return functionAddress;
  } catch (e) {
    return null;
  }
}

function tryParseLdrRegAddress(instruction, pc) {
  if ((instruction & 0xff000000) !== 0x58000000)
    return null;

  const reg = instruction & 0x1f;

  const distance = (instruction >>> 5) & 0x7ffff;
  const imm = pc.add(distance * 4);

  return ['x' + reg, imm];
}

function wrapBlock(handle, wrapper) {
  const block = new ObjC.Block(handle);

  const impl = block.implementation;

  block.implementation = (...args) => wrapper(impl, ...args);

  return block;
}

initialize();

"""

```