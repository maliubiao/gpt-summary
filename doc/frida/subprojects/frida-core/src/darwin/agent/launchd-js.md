Response:
Let's break down the thought process for analyzing this Frida script.

**1. Initial Skim and High-Level Understanding:**

* **Keywords:**  The filename (`launchd.js`), constants like `POSIX_SPAWN_START_SUSPENDED`, `SIGKILL`, and the presence of `Interceptor.attach` immediately suggest this script is about intercepting process creation on macOS/iOS. `launchd` is the system process manager, reinforcing this idea.
* **Core Functionality:** The script seems to be manipulating the process spawning process. The `onEnter` and `onLeave` callbacks for `__posix_spawn` are strong indicators of this.
* **RPC:** The `rpc.exports` section suggests this script exposes functionality to a Frida client. This allows external control and observation of the script's behavior.
* **Jailbreak Quirks:** The `applyJailbreakQuirks` function and related functions like `findJbdCallImpl`, `findSubstrateLauncher`, and `findInserterResume` suggest it also handles scenarios involving jailbroken devices and popular hooking frameworks like Cydia Substrate.

**2. Deeper Dive into Key Sections:**

* **Constants:** Understanding the constants is crucial. `POSIX_SPAWN_START_SUSPENDED` tells us the script can force new processes to start in a paused state. `SIGKILL` indicates a forceful termination.
* **Global Variables:**  Pay attention to global variables like `upcoming`, `gating`, `suspendedPids`, `pidsToIgnore`, `substrateInvocations`, and `substratePidsPending`. These represent the script's state and how it manages intercepted processes. For example, `upcoming` likely tracks apps the user intends to launch.
* **`rpc.exports`:**  Map each exported function to its likely purpose.
    * `dispose`: Clean up, likely killing suspended processes.
    * `prepareForLaunch`:  Indicate intent to launch an app.
    * `cancelLaunch`: Cancel a planned launch.
    * `enableSpawnGating`/`disableSpawnGating`: Control a core feature of the script.
    * `claimProcess`/`unclaimProcess`:  Manage the set of suspended processes.
* **`Interceptor.attach` on `__posix_spawn`:**  This is the heart of the script. Analyze the `onEnter` and `onLeave` logic step-by-step:
    * **`onEnter`:**
        * Argument parsing (`parseStringv`).
        * Identifying the target process (using `xpcproxy` or `XPC_SERVICE_NAME`).
        * Deciding whether to intercept based on `gating`, `reportCrashes`, and `upcoming`.
        * **Crucially**: Setting the `POSIX_SPAWN_START_SUSPENDED` flag. This is a key mechanism for control.
        * Storing context (`this.event`, `this.path`, etc.) for use in `onLeave`.
    * **`onLeave`:**
        * Checking the return value of `posix_spawn`.
        * Adding the spawned PID to `suspendedPids`.
        * Handling Substrate-related scenarios.
        * Sending a message to the Frida backend using `send()`. The message format `[event, path, identifier, pid]` is important.
* **Helper Functions:**  Understand the purpose of functions like `parseStringv`, `isPrewarmLaunch`, and `tryParseXpcServiceName`. These are about extracting information from the arguments of `posix_spawn`.
* **`applyJailbreakQuirks` and Related Functions:**  Recognize that these sections handle specific scenarios on jailbroken devices, likely to bypass or cooperate with existing hooking frameworks. Don't need to understand every detail initially, but understand their general purpose.

**3. Connecting to Reverse Engineering and System Knowledge:**

* **Reverse Engineering:** Think about how this script could be used. Delaying process startup is a powerful debugging and analysis technique. It allows attaching debuggers or performing memory analysis before the application logic starts.
* **macOS/iOS Internals:** Recognize the importance of `launchd`, `posix_spawn`, XPC services, and the role of system libraries like `libsystem_kernel.dylib`.
* **Jailbreaking and Hooking Frameworks:** Knowledge of Cydia Substrate and similar tools is helpful for understanding the `applyJailbreakQuirks` section.

**4. Constructing Examples and Explanations:**

* **Functionality:** Summarize the core actions the script performs.
* **Reverse Engineering Relevance:**  Provide a concrete scenario where the "spawn gating" and delaying startup are beneficial.
* **Binary/Kernel/Framework Knowledge:** Explain the concepts of `posix_spawn`, process IDs, and XPC services.
* **Logic and Assumptions:**  Trace the flow of execution for specific scenarios (e.g., launching an app when `gating` is enabled).
* **User Errors:**  Consider what mistakes a user might make when interacting with the script through the RPC interface.
* **Debugging Clues:**  Explain how a developer would arrive at this code during debugging, focusing on breakpoints and the call stack.

**5. Refinement and Organization:**

* Structure the explanation clearly with headings and bullet points.
* Use precise terminology.
* Provide code snippets where relevant to illustrate points.
* Ensure the examples are concrete and easy to understand.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This just intercepts process creation."  **Correction:**  It does more than just intercept; it actively modifies the spawning behavior (suspending processes).
* **Initial thought:** "The jailbreak code is too complex to understand." **Refinement:** Focus on the *purpose* of these sections (dealing with jailbreak environments) rather than every line of code.
* **Initial thought:**  "How does the user interact with this?" **Realization:** The `rpc.exports` section is the key to user interaction.

By following this structured approach, combining code analysis with system-level knowledge and reverse engineering concepts, you can effectively understand and explain the functionality of a complex Frida script like this one.
这是Frida动态Instrumentation工具的一个JavaScript源代码文件，位于`frida/subprojects/frida-core/src/darwin/agent/`目录下，专门针对Darwin（macOS和iOS）平台的`launchd`进程和进程启动行为进行Hook和控制。

下面我们来详细列举它的功能，并结合逆向、底层知识、逻辑推理以及用户使用等方面进行说明：

**功能列举:**

1. **拦截 `posix_spawn` 系统调用:**  这是该脚本的核心功能。它通过 Frida 的 `Interceptor.attach` 机制，Hook 了 `libsystem_kernel.dylib` 库中的 `__posix_spawn` 函数。这个函数是 macOS 和 iOS 系统中创建新进程的关键系统调用。

2. **控制进程启动状态 (Spawn Gating):**
   - **延迟启动:** 通过在 `posix_spawn` 的 `onEnter` 回调中设置 `POSIX_SPAWN_START_SUSPENDED` 标志，可以强制新创建的进程进入暂停状态。
   - **选择性启动:** 通过 `rpc.exports` 暴露的接口，允许用户指定某些应用（通过 identifier）在启动时被拦截和暂停。`prepareForLaunch` 和 `cancelLaunch` 用于管理这些待启动的应用。
   - **全局开关:** `enableSpawnGating` 和 `disableSpawnGating` 允许用户全局控制是否启用进程启动的拦截和暂停功能。

3. **处理崩溃报告服务:** 可以选择性地拦截和处理崩溃报告服务 (`com.apple.ReportCrash`, `com.apple.osanalytics.osanalyticshelper`) 的启动，这对于调试崩溃问题很有用。`@REPORT_CRASHES@` 可能是构建时注入的配置，用于控制是否启用此功能。

4. **与 Jailbreak 环境的兼容性处理 (Jailbreak Quirks):**  脚本包含 `applyJailbreakQuirks` 函数，用于检测并适配常见的 Jailbreak 环境，例如通过 Cydia Substrate 或 Substitute 注入的进程。
   - **Sabotage `jbd_call`:**  如果检测到 `jbd_call` 函数（与某些 Jailbreak 工具相关），则会Hook它，以避免干扰 Frida 对进程的控制。
   - **Instrument Substrate Launcher:**  如果检测到 Cydia Substrate 的启动器，则会Hook其相关的函数 (`handlePosixSpawn`, `workerCont`)，以确保 Frida 能够正确地与 Substrate 协作。
   - **Instrument Inserter:** 如果检测到 Substitute 的插入器，也会进行Hook。

5. **通过 RPC 接口暴露功能:** 脚本通过 `rpc.exports` 暴露了一系列函数，允许 Frida 客户端（例如 Python 脚本）与此脚本进行交互，控制进程启动行为。

6. **忽略特定进程:**  在处理 Jailbreak 环境时，可能会需要忽略某些由 Jailbreak 工具启动的进程，避免重复处理或冲突。

**与逆向方法的关联及举例说明:**

* **延迟启动以进行调试和分析:** 逆向工程师可以使用此脚本来暂停目标应用的启动，然后手动附加调试器（如 lldb）到该进程，以便在应用执行任何代码之前检查其内存、加载的库、环境变量等。
   * **举例:**  假设你需要逆向分析某个恶意 App 的启动流程。你可以使用 Frida 客户端调用 `rpc.exports.prepareForLaunch("com.example.maliciousapp")` 和 `rpc.exports.enableSpawnGating()`。当该 App 尝试启动时，`launchd.js` 会拦截 `posix_spawn` 并使其进入暂停状态。然后，你可以通过 `frida -p <pid>` 或其他方式将 lldb 连接到这个暂停的进程，设置断点，查看其初始状态。

* **分析启动参数和环境变量:**  在 `posix_spawn` 的 `onEnter` 回调中，脚本可以访问到新进程的启动路径 (`args[1]`) 和环境变量 (`args[4]`)。逆向工程师可以利用这些信息来了解应用是如何被启动的，是否有特殊的启动参数。
   * **举例:**  某些应用可能通过特定的环境变量来配置其行为。你可以使用 Frida 脚本记录下这些环境变量，从而更好地理解应用的内部机制。

* **研究进程间通信 (XPC):**  脚本尝试解析通过 `xpcproxy` 启动的进程的服务标识符 (`rawIdentifier`)。这对于理解使用 XPC 进行进程间通信的应用的架构很有帮助。
   * **举例:**  你可以使用此脚本来监控哪些 XPC 服务被启动，以及与哪些应用关联，从而了解应用的不同模块是如何协作的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层 (macOS/iOS):**
    * **`posix_spawn` 系统调用:**  这是操作系统的底层接口，用于创建新进程。理解其参数（进程路径、参数、环境变量、文件描述符等）对于理解进程启动过程至关重要。脚本中对 `args` 数组的访问就直接对应了这些底层参数。
    * **Mach-O 文件头:** `findClosestMachHeader` 函数用于查找指定地址最近的 Mach-O 文件头。Mach-O 是 macOS 和 iOS 上可执行文件的格式。了解 Mach-O 的结构对于理解代码加载和链接过程很有帮助。
    * **内存扫描 (`Memory.scanSync`):** 脚本中使用内存扫描来查找特定的字节模式，例如在 `findSubstrateLauncher` 中查找 Substrate 相关的字符串或指令序列。这需要对目标进程的内存布局和指令编码有一定的了解。
    * **指令解析 (`Instruction.parse`):** 在 `findInserterResume` 中，脚本尝试解析内存中的指令，以定位特定的代码模式。这需要对汇编语言和指令集架构有了解。

* **Linux 内核 (对比):** 虽然此脚本是针对 Darwin 的，但进程创建的概念在 Linux 中也类似，例如使用 `fork` 和 `execve` 系统调用。理解 Linux 的进程模型可以帮助理解 Darwin 的类似概念。

* **Android 内核及框架 (对比):**  Android 使用 `zygote` 进程来孵化新的应用进程。虽然机制不同，但目标类似：控制应用启动。理解 Android 的进程启动流程可以帮助对比不同操作系统的实现。

**逻辑推理、假设输入与输出:**

* **假设输入:** Frida 客户端调用 `rpc.exports.prepareForLaunch("com.example.testapp")`，然后用户尝试启动 "com.example.testapp"。`rpc.exports.enableSpawnGating()` 已被调用。
* **逻辑推理:**
    1. `prepareForLaunch` 将 "com.example.testapp" 添加到 `upcoming` 集合。
    2. 当系统尝试启动 "com.example.testapp" 时，`__posix_spawn` 被调用。
    3. `onEnter` 回调被触发。
    4. 脚本检查到 `gating` 为 `true`，并且 `rawIdentifier` 匹配 `upcoming` 中的元素。
    5. 设置 `POSIX_SPAWN_START_SUSPENDED` 标志。
    6. `onLeave` 回调被触发。
    7. 新进程的 PID 被添加到 `suspendedPids` 集合。
    8. `send(['launch:app', '/path/to/executable', 'com.example.testapp', pid])` 被调用，将启动事件发送给 Frida 客户端。
* **预期输出:**  Frida 客户端会收到一个消息，指示 "com.example.testapp" 已被启动并暂停，同时提供其 PID。用户可以使用 Frida 客户端调用 `rpc.exports.claimProcess(pid)` 来恢复该进程的执行。

**用户或编程常见的使用错误及举例说明:**

* **忘记启用 Spawn Gating:** 用户调用了 `prepareForLaunch`，但忘记调用 `enableSpawnGating()`，导致目标应用启动时不会被拦截。
   * **举例:** 用户执行了 `frida.rpc.prepareForLaunch("com.example.target")`，但直接启动了目标应用，结果 Frida 没有干预。

* **Identifier 拼写错误:** 用户在 `prepareForLaunch` 中指定的 identifier 与实际应用的 bundle identifier 不符，导致拦截失效。
   * **举例:** 用户想拦截 "com.apple.mobilesafari"，但错误地使用了 `frida.rpc.prepareForLaunch("com.apple.safari")`.

* **在不需要时保持 Spawn Gating 启用:**  用户长时间保持 `enableSpawnGating()` 状态，导致所有新启动的进程都被暂停，影响系统正常运行。

* **与 Jailbreak 工具冲突:** 在 Jailbreak 环境下，如果 Frida 的 Hook 与其他 Jailbreak 工具的 Hook 发生冲突，可能会导致意外行为或崩溃。脚本尝试通过 `applyJailbreakQuirks` 来缓解这种情况，但并非所有冲突都能被解决。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户希望使用 Frida 控制应用启动:**  通常，逆向工程师或安全研究人员希望在目标应用启动时进行干预，例如暂停进程以附加调试器或监控其行为。

2. **编写 Frida 客户端脚本:** 用户会编写一个 Python 或 JavaScript 的 Frida 客户端脚本，使用 Frida 的 API 与目标设备上的 Frida Agent 通信。

3. **在客户端脚本中调用 RPC 接口:**  客户端脚本会调用 `frida.get_usb_device().attach(...)` 或 `frida.spawn(...)` 来连接到目标设备或启动目标应用。然后，它会通过 `session.rpc.exports` 访问 `launchd.js` 暴露的函数。

4. **调用 `prepareForLaunch`:**  客户端脚本会调用 `rpc.exports.prepareForLaunch("com.example.target")`，告知 Frida Agent 准备拦截指定应用的启动。

5. **调用 `enableSpawnGating`:**  客户端脚本会调用 `rpc.exports.enableSpawnGating()`，激活进程启动拦截功能。

6. **系统尝试启动目标应用:**  用户可能通过点击应用图标、其他应用调用 `openURL` 等方式触发目标应用的启动。

7. **`launchd` 进程处理启动请求:** 操作系统会调用 `launchd` 进程来处理应用的启动请求。

8. **`__posix_spawn` 被调用:** `launchd` 最终会调用 `__posix_spawn` 系统调用来创建新的进程。

9. **Frida Agent 的 Hook 生效:** Frida Agent 注入到 `launchd` 进程后，其设置的 `Interceptor.attach` 会拦截对 `__posix_spawn` 的调用。

10. **`launchd.js` 的 `onEnter` 和 `onLeave` 执行:**  `launchd.js` 的 `onEnter` 回调会判断是否需要拦截该进程，并设置暂停标志。`onLeave` 回调会将新进程的 PID 发送回 Frida 客户端。

11. **客户端接收到通知:**  Frida 客户端会接收到 `launchd.js` 发送的通知，告知目标应用已被启动并暂停。

12. **用户在客户端进行后续操作:**  用户可以根据收到的信息，例如使用 PID 将调试器附加到暂停的进程，或者调用 `rpc.exports.claimProcess()` 来恢复进程的执行。

通过以上步骤，用户的操作最终会触发 `launchd.js` 中的代码执行，实现对进程启动的控制。这个文件是 Frida 在 Darwin 平台上实现动态 Instrumentation 的一个关键组成部分。

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/darwin/agent/launchd.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
const POSIX_SPAWN_START_SUSPENDED = 0x0080;
const SIGKILL = 9;

const { pointerSize } = Process;

const crashServices = new Set([
  'com.apple.ReportCrash',
  'com.apple.osanalytics.osanalyticshelper',
]);

const upcoming = new Set();
const reportCrashes = @REPORT_CRASHES@;
let gating = false;
const suspendedPids = new Set();

let pidsToIgnore = null;

const substrateInvocations = new Set();
const substratePidsPending = new Map();

rpc.exports = {
  dispose() {
    if (suspendedPids.size > 0) {
      const kill = new NativeFunction(Module.getExportByName(null, 'kill'), 'int', ['int', 'int']);
      for (const pid of suspendedPids) {
        kill(pid, SIGKILL);
      }
    }
  },
  prepareForLaunch(identifier) {
    upcoming.add(identifier);
  },
  cancelLaunch(identifier) {
    upcoming.delete(identifier);
  },
  enableSpawnGating() {
    gating = true;
  },
  disableSpawnGating() {
    gating = false;
  },
  claimProcess(pid) {
    suspendedPids.delete(pid);
  },
  unclaimProcess(pid) {
    suspendedPids.add(pid);
  },
};

applyJailbreakQuirks();

Interceptor.attach(Module.getExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter(args) {
    const env = parseStringv(args[4]);
    const prewarm = isPrewarmLaunch(env);

    if (prewarm && !gating)
      return;

    const path = args[1].readUtf8String();

    let rawIdentifier;
    if (path === '/usr/libexec/xpcproxy') {
      rawIdentifier = args[3].add(pointerSize).readPointer().readUtf8String();
    } else {
      rawIdentifier = tryParseXpcServiceName(env);
      if (rawIdentifier === null)
        return;
    }

    let identifier, event;
    if (rawIdentifier.startsWith('UIKitApplication:')) {
      identifier = rawIdentifier.substring(17, rawIdentifier.indexOf('['));
      if (!prewarm && upcoming.has(identifier))
        event = 'launch:app';
      else if (gating)
        event = 'spawn';
      else
        return;
    } else if (gating || (reportCrashes && crashServices.has(rawIdentifier))) {
      identifier = rawIdentifier;
      event = 'spawn';
    } else {
      return;
    }

    const attrs = args[2].add(pointerSize).readPointer();

    let flags = attrs.readU16();
    flags |= POSIX_SPAWN_START_SUSPENDED;
    attrs.writeU16(flags);

    this.event = event;
    this.path = path;
    this.identifier = identifier;
    this.pidPtr = args[0];
  },
  onLeave(retval) {
    const { event } = this;
    if (event === undefined)
      return;

    const { path, identifier, pidPtr, threadId } = this;

    if (event === 'launch:app')
      upcoming.delete(identifier);

    if (retval.toInt32() < 0)
      return;

    const pid = pidPtr.readU32();

    suspendedPids.add(pid);

    if (pidsToIgnore !== null)
      pidsToIgnore.add(pid);

    if (substrateInvocations.has(threadId)) {
      substratePidsPending.set(pid, notifyFridaBackend);
    } else {
      notifyFridaBackend();
    }

    function notifyFridaBackend() {
      send([event, path, identifier, pid]);
    }
  }
});

function parseStringv(p) {
  const strings = [];

  if (p.isNull())
    return [];

  let cur = p;
  while (true) {
    const elementPtr = cur.readPointer();
    if (elementPtr.isNull())
      break;

    const element = elementPtr.readUtf8String();
    strings.push(element);

    cur = cur.add(pointerSize);
  }

  return strings;
}

function isPrewarmLaunch(env) {
  return env.some(candidate => candidate.startsWith('ActivePrewarm='));
}

function tryParseXpcServiceName(env) {
  const entry = env.find(candidate => candidate.startsWith('XPC_SERVICE_NAME='));
  if (entry === undefined)
    return null;
  return entry.substring(17);
}

function applyJailbreakQuirks() {
  const jbdCallImpl = findJbdCallImpl();
  if (jbdCallImpl !== null) {
    pidsToIgnore = new Set();
    sabotageJbdCallForOurPids(jbdCallImpl);
    return;
  }

  const launcher = findSubstrateLauncher();
  if (launcher !== null) {
    instrumentSubstrateLauncher(launcher);
    return;
  }

  const inserterResume = findInserterResume();
  if (inserterResume !== null) {
    pidsToIgnore = new Set();
    instrumentInserter(inserterResume);
  }
}

function sabotageJbdCallForOurPids(jbdCallImpl) {
  const retType = 'int';
  const argTypes = ['uint', 'uint', 'uint'];

  const jbdCall = new NativeFunction(jbdCallImpl, retType, argTypes);

  Interceptor.replace(jbdCall, new NativeCallback((port, command, pid) => {
    if (pidsToIgnore.delete(pid))
      return 0;

    return jbdCall(port, command, pid);
  }, retType, argTypes));
}

function instrumentSubstrateLauncher(launcher) {
  Interceptor.attach(launcher.handlePosixSpawn, {
    onEnter() {
      substrateInvocations.add(this.threadId);
    },
    onLeave() {
      substrateInvocations.delete(this.threadId);
    }
  });

  Interceptor.attach(launcher.workerCont, {
    onEnter(args) {
      const baton = args[0];
      const pid = baton.readS32();

      const notify = substratePidsPending.get(pid);
      if (notify !== undefined) {
        substratePidsPending.delete(pid);

        const startSuspendedPtr = baton.add(4);
        startSuspendedPtr.writeU8(1);

        this.notify = notify;
      }
    },
    onLeave(retval) {
      const notify = this.notify;
      if (notify !== undefined)
        notify();
    },
  });
}

function instrumentInserter(at) {
  const original = new NativeFunction(at, 'int', ['uint', 'uint', 'uint', 'uint']);
  Interceptor.replace(at, new NativeCallback((a0, pid, a2, a3) => {
    if (pidsToIgnore.delete(pid))
      return 0;

    return original(a0, pid, a2, a3);
  }, 'int', ['uint', 'uint', 'uint', 'uint']));
}

function findJbdCallImpl() {
  const impl = Module.findExportByName(null, 'jbd_call');
  if (impl !== null)
    return impl;

  const payload = Process.findModuleByName('/chimera/pspawn_payload.dylib');
  if (payload === null)
    return null;

  const matches = Memory.scanSync(payload.base, payload.size, 'ff 43 01 d1 f4 4f 03 a9 fd 7b 04 a9 fd 03 01 91');
  if (matches.length !== 1)
    throw new Error('Unsupported version of Chimera; please file a bug');

  return matches[0].address;
}

function findSubstrateLauncher() {
  if (Process.arch !== 'arm64')
    return null;

  const imp = Module.enumerateImports('/sbin/launchd').filter(imp => imp.name === 'posix_spawn')[0];
  if (imp === undefined)
    return null;
  const impl = imp.slot.readPointer().strip();
  const header = findClosestMachHeader(impl);

  const launcherDylibName = stringToHexPattern('Launcher.t.dylib');
  const isSubstrate = Memory.scanSync(header, 2048, launcherDylibName).length > 0;
  if (!isSubstrate)
    return null;

  const atvLauncherDylibName = stringToHexPattern('build.atv/Launcher.t.dylib');
  const isATVSubstrate = Memory.scanSync(header, 2048, atvLauncherDylibName).length > 0;

  return {
    handlePosixSpawn: resolveFunction('handlePosixSpawn',
      isATVSubstrate
      ? 'fc 6f ba a9 fa 67 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 ff 83 02 d1 e6 1f 00 f9'
      : 'fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 f8 5f bf a9 fa 67 bf a9 fc 6f bf a9 ff 43 04 d1'),
    workerCont: resolveFunction('workerCont',
      isATVSubstrate
      ? 'f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 ff 83 00 d1 f3 03 00 aa c3 fc ff 97 f4 03 00 aa'
      : 'fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 f8 5f bf a9 fa 67 bf a9 fc 6f bf a9 ff 43 01 d1'),
  };

  function resolveFunction(name, signature) {
    const matches = Memory.scanSync(header, 37056, signature);
    if (matches.length !== 1) {
      throw new Error(`Unsupported version of Substrate; please file a bug: ${name} matched ${matches.length} times`);
    }
    return matches[0].address;
  }
}

function stringToHexPattern(str) {
  return str.split('').map(o => o.charCodeAt(0).toString(16)).join(' ');
}

function findClosestMachHeader(address) {
  let cur = address.and(ptr(4095).not());
  while (true) {
    if ((cur.readU32() & 0xfffffffe) >>> 0 === 0xfeedface)
      return cur;
    cur = cur.sub(4096);
  }
}

function findInserterResume() {
  const candidates = Process.enumerateModules().filter(x => x.name === 'substitute-inserter.dylib');
  if (candidates.length !== 1)
    return null;

  const { base, size } = candidates[0];
  const signature = 'e0 03 00 91 e1 07 00 32 82 05 80 52 83 05 80 52 05 00 80 52';

  const matches = Memory.scanSync(base, size, signature);
  if (matches.length !== 1)
    return null;

  let cursor = matches[0].address.sub(4);
  const end = cursor.sub(1024);
  while (cursor.compare(end) >= 0) {
    try {
      const instr = Instruction.parse(cursor);
      if (instr.mnemonic.startsWith('ret'))
        return cursor.add(4).sign();
    } catch (e) {
    }
    cursor = cursor.sub(4);
  }

  return null;
}

"""

```