Response:
Let's break down the thought process for analyzing this Python Frida script.

**1. Initial Understanding - What is the Goal?**

The file name `Capture.py` and the import of `frida` and `PyObjCTools` immediately suggest this is a tool for capturing and analyzing something. The presence of `device`, `session`, `script`, `modules`, and `calls` points towards interaction with a target process. The name "cpushark" in the path gives a strong hint it's related to CPU activity or tracing.

**2. High-Level Structure and Workflow:**

I start by looking at the main class, `Capture`. Its methods like `attachToProcess_triggerPort_`, `detach`, `_doAttachWithParams_`, and `_doDetachWithParams_` clearly define the lifecycle of a capture session. The use of `NSThread` indicates asynchronous operations, likely necessary due to Frida's interaction with a potentially unresponsive target process.

**3. Key Components and Their Roles:**

* **`Capture`:**  Manages the entire capture process, including attaching, detaching, and handling communication with the Frida script.
* **`CaptureState`:**  An enumeration to track the current state of the capture.
* **`Modules`:** Responsible for retrieving and storing information about the loaded modules in the target process.
* **`Module`:** Represents a single module in the target process.
* **`Calls`:**  The core component for handling function call information. It manages probes, aggregates call counts, and presents call stacks.
* **`TargetModule` and `TargetFunction`:** Represent aggregated call information for specific modules and functions.
* **`FunctionCall`:** Represents a single instance of a function call with its arguments.
* **`SCRIPT_TEMPLATE`:** This is the JavaScript code injected into the target process by Frida. It's crucial for understanding the underlying instrumentation.

**4. Delving into the Frida Script (`SCRIPT_TEMPLATE`):**

This is where the *dynamic instrumentation* happens. I break down the script's functionality:

* **`Stalker`:**  This is the key Frida API for tracing execution. The script initializes `Stalker` to capture function calls.
* **`sendModules`:**  Uses `Process.enumerateModules` to get a list of loaded modules and sends this information back to the Python side.
* **`interceptReadFunction`:** This is a crucial part. It intercepts `recv`, `read$UNIX2003`, and `readv$UNIX2003` functions from `libSystem.B.dylib`. The conditional logic based on the socket's peer address and the `trigger_port` is vital for understanding *when* the tracing starts.
* **`onStanza`:** Handles messages sent from the Python side to add or remove probes using `Stalker.addCallProbe` and `Stalker.removeCallProbe`.
* **`probes` object:** Stores the IDs of the active call probes.
* **`onCallSummary`:**  This is where the call data is sent back to the Python side.
* **`setTimeout(initialize, 0)`:**  Ensures the initialization runs after the script is loaded.

**5. Connecting Python and JavaScript:**

I pay attention to how the Python code interacts with the injected JavaScript:

* **`script.create_script(source=SCRIPT_TEMPLATE)`:**  The Python code injects the JavaScript.
* **`script.on("message", self._onScriptMessage)`:** The Python code registers a handler for messages sent from the JavaScript side.
* **`script.post(message)`:** The Python code sends messages to the JavaScript side (for adding/removing probes).
* **`send({...})` in JavaScript:** This sends messages back to the Python side.

**6. Analyzing Functionality and Relation to Reverse Engineering:**

Now I can systematically answer the prompt's questions:

* **Functionality:** List each class and method and describe what it does. Focus on the core actions: attaching, detaching, capturing modules, intercepting functions, managing probes, and presenting call data.
* **Reverse Engineering:** The script uses dynamic instrumentation to understand the runtime behavior of a process. This is a core technique in reverse engineering. I give concrete examples like observing API calls and their arguments to understand a program's interaction with the system.
* **Binary/Kernel/Framework Knowledge:** The script interacts with low-level concepts like process IDs, memory addresses, modules, and system libraries. The interception of `recv`, `read`, and `readv` directly relates to network communication, a fundamental part of operating system interaction. Mentioning `libSystem.B.dylib` specifies a system library on macOS (or a similar Unix-like system). The `trigger_port` concept hints at a specific network trigger.
* **Logical Inference:** The script infers function calls based on the `Stalker` output. I create a simple input/output scenario for adding a probe and observing a call.
* **User/Programming Errors:**  Think about common mistakes: trying to attach to a non-existent process, attaching when already attached, incorrect port numbers, etc.
* **User Operation Flow:** Imagine the user interacting with a hypothetical GUI or command-line interface that uses this `Capture` class. Describe the steps leading to the execution of the code.

**7. Structuring the Answer:**

Finally, organize the information logically, using clear headings and bullet points. Provide specific code snippets where relevant to illustrate the points. The goal is to provide a comprehensive and easy-to-understand explanation of the code's functionality and its relation to the concepts mentioned in the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the script captures *all* function calls. **Correction:** The `interceptReadFunction` and the `trigger_port` logic indicate a more targeted approach, likely triggered by specific network activity.
* **Realization:**  The `PROBE_CALLS` regex and the `_probes` dictionary in the `Calls` class are critical for understanding how individual function calls are monitored after the initial trigger.
* **Emphasis:** The `SCRIPT_TEMPLATE` is the *engine* of the dynamic instrumentation, so it needs a detailed explanation.

By following this structured approach, combining code analysis with knowledge of Frida and system-level concepts, I can effectively analyze and explain the functionality of the provided Python script.
这是一个名为 `Capture.py` 的 Python 脚本，它是 `fridaDynamic` 动态插桩工具的一部分，用于捕获目标进程的执行信息，特别是函数调用。 让我们分解一下它的功能以及与您提到的概念的关联：

**主要功能:**

1. **进程附加与分离:**
   - `attachToProcess_triggerPort_(self, process, triggerPort)`:  附加到目标进程。它接受一个 `process` 对象（代表要附加的进程）和一个 `triggerPort`。这个 `triggerPort` 很重要，它定义了一个 TCP 端口，当目标进程与该端口建立连接时，才会开始详细的函数调用追踪。
   - `detach(self)`: 从目标进程分离，停止追踪。

2. **Frida 脚本管理:**
   - 使用 `frida` 库创建并加载一个 JavaScript 脚本 (定义在 `SCRIPT_TEMPLATE`) 到目标进程中。这个脚本负责实际的插桩和数据收集工作。
   - `_onScriptMessage(self, message, data)`: 接收从注入的 JavaScript 脚本发送回来的消息。这些消息包含模块信息、函数调用信息等。
   - `_post(self, message)`: 向注入的 JavaScript 脚本发送消息，例如添加或移除函数调用探针。

3. **模块信息管理:**
   - `Modules` 类：负责获取并存储目标进程加载的模块信息（名称、基址、大小）。
   - `_sync(self, payload)`:  处理从 JavaScript 脚本接收到的模块同步消息，更新模块列表。
   - `lookup(self, addr)`:  根据给定的内存地址查找所属的模块。

4. **函数调用追踪和管理:**
   - `Calls` 类：负责管理追踪到的函数调用信息。
   - `addProbe_(self, func)`:  向 JavaScript 脚本发送指令，在指定的函数地址上设置一个调用探针。当目标进程执行到该函数时，会记录其调用信息。
   - `removeProbe_(self, func)`:  移除指定函数地址上的调用探针。
   - `_add_(self, data)`: 处理从 JavaScript 脚本接收到的函数调用汇总信息。它统计每个模块和函数的调用次数。
   - `_handleStanza_(self, stanza)`:  处理从 JavaScript 脚本接收到的特定函数调用探针的消息，包含函数调用的参数。

5. **状态管理:**
   - `CaptureState` 枚举：维护捕获的当前状态（DETACHED, ATTACHING, ATTACHED）。
   - `_updateState_(self, newState)`:  更新捕获状态并通知代理对象。

6. **委托模式:**
   - 使用 `delegate` 属性（通常遵循 Cocoa 的委托模式）将捕获状态变化、接收到新数据等事件通知给其他对象（例如 GUI）。

**与逆向方法的关联:**

这个脚本是逆向工程中**动态分析**的一种典型应用。

* **观察程序行为:** 通过动态插桩，可以实时观察目标进程的函数调用、参数等信息，了解程序的执行流程和行为模式。这对于理解不熟悉的代码或者分析恶意软件非常有用。
* **API 监控:**  `SCRIPT_TEMPLATE` 中拦截了 `recv`, `read$UNIX2003`, `readv$UNIX2003` 这些与网络通信相关的 API 调用。逆向工程师可以通过监控这些 API 的调用，了解程序是否在进行网络通信，以及通信的内容。
* **函数调用栈分析:**  虽然这个脚本本身没有显式地展示完整的调用栈，但通过 `Stalker` 收集的 `onCallSummary` 信息以及设置的探针，可以推断出函数的调用关系。更复杂的逆向分析工具可能会进一步解析这些信息以构建完整的调用栈。
* **漏洞分析:** 通过监控关键函数的调用和参数，可以发现潜在的安全漏洞，例如缓冲区溢出、格式化字符串漏洞等。

**举例说明:**

假设我们要逆向分析一个网络应用程序，想知道它在接收到特定数据后会调用哪些函数。

1. **附加进程:** 使用 `attachToProcess_triggerPort_` 附加到目标进程，并设置一个 `triggerPort`，例如 12345。
2. **触发行为:**  向目标应用程序发送网络数据，使其与端口 12345 建立连接。
3. **开始追踪:** 当连接建立后，`SCRIPT_TEMPLATE` 中的 JavaScript 代码会检测到与 `triggerPort` 的连接，然后开始使用 `Stalker` 追踪函数调用。
4. **设置探针:**  通过 `addProbe_` 方法，可以在我们感兴趣的函数上设置探针，例如某个处理网络数据的关键函数。
5. **捕获调用:** 当目标进程执行到设置了探针的函数时，JavaScript 脚本会将该调用的参数信息发送回 Python 脚本。
6. **分析结果:** Python 脚本接收并展示这些调用信息，帮助我们理解该函数的行为。

**涉及二进制底层，Linux, Android 内核及框架的知识:**

* **二进制底层:**
    - **内存地址:**  脚本中大量使用了内存地址，例如模块的基址、函数的地址。这些都是二进制层面的概念。
    - **函数调用约定:**  `SCRIPT_TEMPLATE` 中的探针 (`Stalker.addCallProbe`) 会捕获函数调用的参数。理解目标平台的函数调用约定（例如 x86-64 的寄存器传参或栈传参）有助于理解捕获到的参数的意义。
* **Linux/Android 内核:**
    - **系统调用:** `recv`, `read`, `readv` 是常见的系统调用，用于进行底层 I/O 操作。理解这些系统调用的作用是理解脚本功能的基础。
    - **动态链接库 (`libSystem.B.dylib`):**  脚本中拦截了 `libSystem.B.dylib` 中的函数。这是 macOS (以及 iOS) 上的一个核心系统库，包含了许多基础的 C 运行时函数和系统调用封装。在 Linux 上，类似的库可能是 `libc.so`。在 Android 上，可能是 `libc.so` 或 `bionic` 库。
    - **进程和线程:**  Frida 需要与目标进程进行交互，理解进程 ID (PID)、线程 ID 等概念是必要的。脚本中使用了 `Process.getCurrentThreadId()`。
* **框架 (可能指 Android Framework):**
    - 如果目标是 Android 应用程序，那么被拦截的函数可能属于 Android Framework 的一部分。理解 Android Framework 的结构和关键 API 有助于理解捕获到的调用。
    - `Socket.type(fd)`, `Socket.peerAddress(fd)` 等 Frida 提供的 API 封装了底层 socket 操作，这些操作在不同操作系统上可能有所不同。

**举例说明:**

- **二进制底层:**  `addProbe_` 方法中，函数地址被格式化为十六进制字符串 `"0x%x" % func.address`。
- **Linux/Android 内核:**  拦截的 `recv`, `read$UNIX2003`, `readv$UNIX2003` 函数都是与底层文件描述符和 I/O 操作相关的系统调用。
- **框架:** 如果目标是 Android 应用，`trigger_port` 可能用于监控应用与特定服务器的通信，而拦截的函数可能涉及 Android 的网络栈。

**逻辑推理 (假设输入与输出):**

假设：

* **输入:** 用户使用 GUI 或命令行工具，指定要附加的进程 PID 为 1234，`triggerPort` 为 8888。
* **操作:** 用户点击“开始捕获”按钮，触发 `attachToProcess_triggerPort_(process, 8888)` 调用。
* **JavaScript 脚本执行:**  脚本被注入到 PID 1234 的进程中。
* **目标进程行为:**  目标进程尝试连接到远程服务器，恰好也连接到了本地的 8888 端口（可能是一个巧合，或者目标程序本身就在监听这个端口）。
* **探针设置:** 用户通过界面添加了一个对地址 `0x7ffff7a12340` 的函数的探针。

**输出:**

1. **状态变化:** `Capture` 的状态会从 `DETACHED` 变为 `ATTACHING`，然后变为 `ATTACHED`。GUI 可能会显示 "正在连接..." 和 "已连接" 等状态。
2. **模块信息:**  `Modules` 类会接收到来自 JavaScript 脚本的模块信息，包含进程中加载的所有库的名称、基址和大小。
3. **拦截器触发:** 当目标进程执行到 `recv` 等被拦截的函数，并且连接的目标端口是 8888 时，`interceptReadFunction` 的 `onLeave` 逻辑会执行。
4. **开始追踪:** `Stalker.follow` 被调用，开始追踪 PID 1234 进程的调用。
5. **探针命中:** 当目标进程调用地址为 `0x7ffff7a12340` 的函数时，JavaScript 脚本中的探针会捕获到这次调用，并将参数信息发送回 Python 脚本。
6. **调用信息显示:**  `Calls` 类会处理接收到的探针信息，并在 GUI 上显示该函数的调用，可能包含参数值，例如：`sub_12340(0x1, 0x7fffffffd020, 0x4, 0x0)`。
7. **调用统计:** `Calls` 类还会统计每个模块和函数的调用次数。

**用户或编程常见的使用错误:**

1. **尝试附加到不存在的进程:** 如果提供的 PID 不对应于任何正在运行的进程，Frida 会抛出异常，导致附加失败。
2. **在已附加时再次尝试附加:**  脚本中有 `assert self.state == CaptureState.DETACHED` 的断言，如果状态不是 `DETACHED`，会抛出异常。
3. **`triggerPort` 设置错误:**  如果 `triggerPort` 设置错误，或者目标进程没有连接到该端口，则 `Stalker` 不会启动，无法捕获到函数调用。
4. **依赖于特定的库名:**  `interceptReadFunction` 中硬编码了 `libSystem.B.dylib`。如果目标程序运行在其他操作系统上，例如 Linux 或 Windows，则需要修改脚本以适应不同的库名 (`libc.so` 或 `ws2_32.dll` 等)。
5. **假设参数数量和类型:** `SCRIPT_TEMPLATE` 中探针捕获固定数量的参数 (`args[0]` 到 `args[3]`)。如果被探针的函数参数数量不同，会导致错误或信息丢失。
6. **忘记分离:**  在不需要追踪时忘记调用 `detach()` 可能导致资源泄漏或影响目标进程的性能。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 客户端应用程序或执行 Frida 命令行工具。**
2. **用户指定目标进程:**  用户可能通过 PID 或进程名称指定要分析的目标进程。
3. **用户配置捕获参数:** 用户设置了 `triggerPort` 的值，可能是在一个配置界面或者命令行参数中指定的。
4. **用户触发“开始捕获”操作:**  用户点击按钮或执行命令，导致客户端代码调用 `Capture.py` 中的 `attachToProcess_triggerPort_` 方法，并将目标进程对象和 `triggerPort` 传递给它。
5. **`attachToProcess_triggerPort_` 创建新的线程 `_doAttachWithParams_` 来执行附加操作，防止阻塞主线程。**
6. **在 `_doAttachWithParams_` 中，Frida 尝试连接到目标进程。**
7. **如果连接成功，Frida 创建一个脚本对象，并加载 `SCRIPT_TEMPLATE` 中的 JavaScript 代码到目标进程中。**
8. **JavaScript 脚本开始执行，并监听目标进程与 `triggerPort` 的连接。**
9. **用户可能通过 GUI 或命令行界面，指定要添加探针的函数地址，这会调用 `Calls` 类的 `addProbe_` 方法。**
10. **`addProbe_` 方法会将添加探针的消息发送到注入的 JavaScript 脚本。**

通过以上步骤，用户操作最终导致了 `Capture.py` 中相关代码的执行，从而实现了动态插桩和函数调用捕获的功能。在调试过程中，可以检查每个步骤的状态和变量值，例如 `self.state` 的变化，`self.session` 和 `self.script` 是否被正确创建，以及是否成功接收到来自 JavaScript 脚本的消息，来定位问题。

### 提示词
```
这是目录为frida/subprojects/frida-python/examples/cpushark/Capture.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import bisect
import re

from Foundation import NSAutoreleasePool, NSObject, NSThread
from PyObjCTools import AppHelper

PROBE_CALLS = re.compile(r"^\/stalker\/probes\/(.*?)\/calls$")


class Capture(NSObject):
    def __new__(cls, device):
        return cls.alloc().initWithDevice_(device)

    def initWithDevice_(self, device):
        self = self.init()
        self.state = CaptureState.DETACHED
        self.device = device
        self._delegate = None
        self.session = None
        self.script = None
        self.modules = Modules()
        self.recvTotal = 0
        self.calls = Calls(self)
        return self

    def delegate(self):
        return self._delegate

    def setDelegate_(self, delegate):
        self._delegate = delegate

    def attachToProcess_triggerPort_(self, process, triggerPort):
        assert self.state == CaptureState.DETACHED
        self._updateState_(CaptureState.ATTACHING)
        NSThread.detachNewThreadSelector_toTarget_withObject_("_doAttachWithParams:", self, (process.pid, triggerPort))

    def detach(self):
        assert self.state == CaptureState.ATTACHED
        session = self.session
        script = self.script
        self.session = None
        self.script = None
        self._updateState_(CaptureState.DETACHED)
        NSThread.detachNewThreadSelector_toTarget_withObject_("_doDetachWithParams:", self, (session, script))

    def _post(self, message):
        NSThread.detachNewThreadSelector_toTarget_withObject_("_doPostWithParams:", self, (self.script, message))

    def _updateState_(self, newState):
        self.state = newState
        self._delegate.captureStateDidChange()

    def _doAttachWithParams_(self, params):
        pid, triggerPort = params
        pool = NSAutoreleasePool.alloc().init()
        session = None
        script = None
        error = None
        try:
            session = self.device.attach(pid)
            session.on("detached", self._onSessionDetached)
            script = session.create_script(name="cpushark", source=SCRIPT_TEMPLATE % {"trigger_port": triggerPort})
            script.on("message", self._onScriptMessage)
            script.load()
        except Exception as e:
            if session is not None:
                try:
                    session.detach()
                except:
                    pass
                session = None
            script = None
            error = e
        AppHelper.callAfter(self._attachDidCompleteWithSession_script_error_, session, script, error)
        del pool

    def _doDetachWithParams_(self, params):
        session, script = params
        pool = NSAutoreleasePool.alloc().init()
        try:
            script.unload()
        except:
            pass
        try:
            session.detach()
        except:
            pass
        del pool

    def _doPostWithParams_(self, params):
        script, message = params
        pool = NSAutoreleasePool.alloc().init()
        try:
            script.post(message)
        except Exception as e:
            print("Failed to post to script:", e)
        del pool

    def _attachDidCompleteWithSession_script_error_(self, session, script, error):
        if self.state == CaptureState.ATTACHING:
            self.session = session
            self.script = script
            if error is None:
                self._updateState_(CaptureState.ATTACHED)
            else:
                self._updateState_(CaptureState.DETACHED)
                self._delegate.captureFailedToAttachWithError_(error)

    def _sessionDidDetach(self):
        if self.state == CaptureState.ATTACHING or self.state == CaptureState.ATTACHED:
            self.session = None
            self._updateState_(CaptureState.DETACHED)

    def _sessionDidReceiveMessage_data_(self, message, data):
        if message["type"] == "send":
            stanza = message["payload"]
            fromAddress = stanza["from"]
            name = stanza["name"]
            if fromAddress == "/process/modules" and name == "+sync":
                self.modules._sync(stanza["payload"])
            elif fromAddress == "/stalker/calls" and name == "+add":
                self.calls._add_(stanza["payload"])
            elif fromAddress == "/interceptor/functions" and name == "+add":
                self.recvTotal += 1
                self._delegate.captureRecvTotalDidChange()
            else:
                if not self.calls._handleStanza_(stanza):
                    print(f"Woot! Got stanza: {stanza['name']} from={stanza['from']}")
        else:
            print("Unhandled message:", message)

    def _onSessionDetached(self):
        AppHelper.callAfter(self._sessionDidDetach)

    def _onScriptMessage(self, message, data):
        AppHelper.callAfter(self._sessionDidReceiveMessage_data_, message, data)


class CaptureState:
    DETACHED = 1
    ATTACHING = 2
    ATTACHED = 3


class Modules:
    def __init__(self):
        self._modules = []
        self._indices = []

    def _sync(self, payload):
        modules = []
        for item in payload["items"]:
            modules.append(Module(item["name"], int(item["base"], 16), item["size"]))
        modules.sort(lambda x, y: x.address - y.address)
        self._modules = modules
        self._indices = [m.address for m in modules]

    def lookup(self, addr):
        idx = bisect.bisect(self._indices, addr)
        if idx == 0:
            return None
        m = self._modules[idx - 1]
        if addr >= m.address + m.size:
            return None
        return m


class Module:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size

    def __repr__(self):
        return "(%d, %d, %s)" % (self.address, self.size, self.name)


class Calls(NSObject):
    def __new__(cls, capture):
        return cls.alloc().initWithCapture_(capture)

    def initWithCapture_(self, capture):
        self = self.init()
        self.capture = capture
        self.targetModules = []
        self._targetModuleByAddress = {}
        self._delegate = None
        self._probes = {}
        return self

    def delegate(self):
        return self._delegate

    def setDelegate_(self, delegate):
        self._delegate = delegate

    def addProbe_(self, func):
        self.capture._post({"to": "/stalker/probes", "name": "+add", "payload": {"address": "0x%x" % func.address}})
        self._probes[func.address] = func

    def removeProbe_(self, func):
        self.capture._post({"to": "/stalker/probes", "name": "+remove", "payload": {"address": "0x%x" % func.address}})
        self._probes.pop(func.address, None)

    def _add_(self, data):
        modules = self.capture.modules
        for rawTarget, count in data["summary"].items():
            target = int(rawTarget, 16)
            tm = self.getTargetModuleByModule_(modules.lookup(target))
            if tm is not None:
                tm.total += count
                tf = tm.getTargetFunctionByAddress_(target)
                tf.total += count

        self.targetModules.sort(key=lambda tm: tm.total, reverse=True)
        for tm in self.targetModules:
            tm.functions.sort(self._compareFunctions)
        self._delegate.callsDidChange()

    def _compareFunctions(self, x, y):
        if x.hasProbe == y.hasProbe:
            return x.total - y.total
        elif x.hasProbe:
            return -1
        elif y.hasProbe:
            return 1
        else:
            return x.total - y.total

    def _handleStanza_(self, stanza):
        m = PROBE_CALLS.match(stanza["from"])
        if m is not None:
            func = self._probes.get(int(m.groups()[0], 16), None)
            if func is not None:
                if len(func.calls) == 3:
                    func.calls.pop(0)
                func.calls.append(FunctionCall(func, stanza["payload"]["args"]))
                self._delegate.callItemDidChange_(func)
            return True
        return False

    def getTargetModuleByModule_(self, module):
        if module is None:
            return None
        tm = self._targetModuleByAddress.get(module.address, None)
        if tm is None:
            tm = TargetModule(module)
            self.targetModules.append(tm)
            self._targetModuleByAddress[module.address] = tm
        return tm

    def outlineView_numberOfChildrenOfItem_(self, outlineView, item):
        if item is None:
            return len(self.targetModules)
        elif isinstance(item, TargetModule):
            return len(item.functions)
        elif isinstance(item, TargetFunction):
            return len(item.calls)
        else:
            return 0

    def outlineView_isItemExpandable_(self, outlineView, item):
        if item is None:
            return False
        elif isinstance(item, TargetModule):
            return len(item.functions) > 0
        elif isinstance(item, TargetFunction):
            return len(item.calls) > 0
        else:
            return False

    def outlineView_child_ofItem_(self, outlineView, index, item):
        if item is None:
            return self.targetModules[index]
        elif isinstance(item, TargetModule):
            return item.functions[index]
        elif isinstance(item, TargetFunction):
            return item.calls[index]
        else:
            return None

    def outlineView_objectValueForTableColumn_byItem_(self, outlineView, tableColumn, item):
        identifier = tableColumn.identifier()
        if isinstance(item, TargetModule):
            if identifier == "name":
                return item.module.name
            elif identifier == "total":
                return item.total
            else:
                return False
        elif isinstance(item, TargetFunction):
            if identifier == "name":
                return item.name
            elif identifier == "total":
                return item.total
            else:
                return item.hasProbe
        else:
            if identifier == "name":
                return item.summary
            elif identifier == "total":
                return ""
            else:
                return False


class TargetModule(NSObject):
    def __new__(cls, module):
        return cls.alloc().initWithModule_(module)

    def initWithModule_(self, module):
        self = self.init()
        self.module = module
        self.functions = []
        self._functionByAddress = {}
        self.total = 0
        return self

    def getTargetFunctionByAddress_(self, address):
        f = self._functionByAddress.get(address, None)
        if f is None:
            f = TargetFunction(self, address - self.module.address)
            self.functions.append(f)
            self._functionByAddress[address] = f
        return f


class TargetFunction(NSObject):
    def __new__(cls, module, offset):
        return cls.alloc().initWithModule_offset_(module, offset)

    def initWithModule_offset_(self, targetModule, offset):
        self = self.init()
        self.name = "sub_%x" % offset
        self.module = targetModule
        self.address = targetModule.module.address + offset
        self.offset = offset
        self.total = 0
        self.hasProbe = False
        self.calls = []
        return self


class FunctionCall(NSObject):
    def __new__(cls, func, args):
        return cls.alloc().initWithFunction_args_(func, args)

    def initWithFunction_args_(self, func, args):
        self = self.init()
        self.func = func
        self.args = args
        self.summary = f"{func.name}({', '.join(args)})"
        return self


SCRIPT_TEMPLATE = """
var probes = Object.create(null);

var initialize = function initialize() {
    Stalker.trustThreshold = 2000;
    Stalker.queueCapacity = 1000000;
    Stalker.queueDrainInterval = 250;

    sendModules(function () {
        interceptReadFunction('recv');
        interceptReadFunction('read$UNIX2003');
        interceptReadFunction('readv$UNIX2003');
    });

    recv(onStanza);
};

var onStanza = function onStanza(stanza) {
    if (stanza.to === "/stalker/probes") {
        var address = stanza.payload.address,
            probeId;
        switch (stanza.name) {
            case '+add':
                if (probes[address] === undefined) {
                    var probeAddress = "/stalker/probes/" + address + "/calls";
                    probeId = Stalker.addCallProbe(ptr(address), function probe(args) {
                        var data = [
                            "0x" + args[0].toString(16),
                            "0x" + args[1].toString(16),
                            "0x" + args[2].toString(16),
                            "0x" + args[3].toString(16)
                        ];
                        send({ from: probeAddress, name: '+add', payload: { args: data } });
                    });
                    probes[address] = probeId;
                }
                break;
            case '+remove':
                probeId = probes[address];
                if (probeId !== undefined) {
                    Stalker.removeCallProbe(probeId);
                    delete probes[address];
                }
                break;
        }
    }

    recv(onStanza);
};

var sendModules = function sendModules(callback) {
    var modules = [];
    Process.enumerateModules({
        onMatch: function onMatch(module) {
            modules.push(module);
        },
        onComplete: function onComplete() {
            send({ name: '+sync', from: "/process/modules", payload: { items: modules } });
            callback();
        }
    });
};

var stalkedThreadId = null;
var interceptReadFunction = function interceptReadFunction(functionName) {
    Interceptor.attach(Module.getExportByName('libSystem.B.dylib', functionName), {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
        },
        onLeave: function (retval) {
            var fd = this.fd;
            if (Socket.type(fd) === 'tcp') {
                var address = Socket.peerAddress(fd);
                if (address !== null && address.port === %(trigger_port)d) {
                    send({ name: '+add', from: "/interceptor/functions", payload: { items: [{ name: functionName }] } });
                    if (stalkedThreadId === null) {
                        stalkedThreadId = Process.getCurrentThreadId();
                        Stalker.follow(stalkedThreadId, {
                            events: {
                                call: true
                            },
                            onCallSummary: function onCallSummary(summary) {
                                send({ name: '+add', from: "/stalker/calls", payload: { summary: summary } });
                            }
                        });
                    }
                }
            }
        }
    });
}

setTimeout(initialize, 0);
"""
```