Response:
The user wants a summary of the functionality of the provided Python code snippet, which is part of Frida's core library. I need to go through each class and method, explain its purpose, and connect it to reverse engineering concepts, binary/kernel knowledge, and potential user errors.

Here's a breakdown of how to approach this:

1. **Identify the Core Components:**  The code defines several classes: `Device`, `DeviceManager`, `EndpointParameters`, `PortalService`, `Compiler`, and `Cancellable`. These are the primary building blocks of the functionality.

2. **Analyze Each Class:** For each class, I will:
    * **Describe its purpose:** What problem does this class solve? What kind of functionality does it encapsulate?
    * **Identify key methods:** What are the main actions you can perform with this class?
    * **Relate to reverse engineering:** How can these methods be used in a reverse engineering context?
    * **Connect to low-level concepts:** Does the class interact with the operating system, kernel, or hardware?
    * **Consider user errors:** What mistakes might a user make when using this class?
    * **Hypothesize input/output for logical operations:** If there's decision-making logic, provide examples.

3. **Pay Attention to Decorators and Type Hints:** The `@overload` decorator indicates different signatures for the same method, which is important for understanding how the method can be used. Type hints provide valuable information about the expected data types.

4. **Address Specific Instructions:**
    * **Reverse Engineering:** Explicitly point out how each component is useful for reverse engineering.
    * **Binary/Kernel/Framework:** Highlight interactions with the underlying system.
    * **Logic/Inference:** Provide concrete examples of input and output.
    * **User Errors:** Give practical examples of common mistakes.
    * **User Steps to Reach Here:**  Think about the typical Frida workflow that would lead to using these classes.
    * **Overall Summary:**  Concisely summarize the main purpose of the code.

5. **Structure the Output:** Organize the information clearly, perhaps by class, to make it easy to understand. Use headings and bullet points.

**Mental Walkthrough of the Code:**

* **`Device`:** Represents a target device (local, remote, USB). Key for connecting to and interacting with a system.
* **`DeviceManager`:**  Manages the collection of connected devices. Allows you to find and select a target device.
* **`EndpointParameters`:**  Configuration for network connections, used by `PortalService`.
* **`PortalService`:** Enables creating a service to communicate with Frida clients. Useful for custom communication channels.
* **`Compiler`:**  Handles the compilation of Frida scripts. Important for packaging and deploying scripts.
* **`Cancellable`:** Provides a mechanism for cancelling long-running operations. Good practice for robust scripting.

**Example of Detailed Analysis (for `Device` class):**

* **Purpose:** Represents a single device where Frida can run.
* **Key Methods:** `attach()`, `spawn()`, `inject_library()`, `on()`, `off()`.
* **Reverse Engineering:** `attach()` connects to running processes for inspection and modification. `spawn()` launches new processes under Frida's control. `inject_library()` is core to Frida's instrumentation by loading code into the target. `on()` and `off()` for event handling are useful for monitoring device activity.
* **Binary/Kernel:** Interacts with the OS process management and potentially kernel-level APIs for hooking.
* **User Errors:** Trying to attach to a non-existent process, incorrect process name or ID.
* **Logic Example:** `_pid_of()`: Input: process name string (e.g., "com.example.app") or PID integer (e.g., 1234). Output: Integer PID. Assumes the process exists if a name is given and `get_process()` succeeds.

By following this detailed approach for each class and considering all the requirements, I can construct a comprehensive and informative summary.
好的，这是第二部分对 `frida/subprojects/frida-python/frida/core.py` 文件功能的归纳总结：

**整体功能归纳：**

延续第一部分的描述，`frida/subprojects/frida-python/frida/core.py` 文件继续定义了 Frida 动态插桩框架的核心组件，主要围绕以下几个方面展开：

1. **设备管理与发现 (`DeviceManager`):** 提供了管理和发现 Frida 能够连接的设备的能力，包括本地设备、远程设备和 USB 设备。
2. **远程连接管理 (`EndpointParameters`, `DeviceManager.add_remote_device`, `DeviceManager.remove_remote_device`):**  定义了远程连接的参数，并提供了添加和移除远程 Frida Agent 的功能。
3. **Portal 服务 (`PortalService`):**  允许创建和管理一个 Portal 服务，用于 Frida 客户端之间的通信和协作，支持消息的发送、广播、标记等。
4. **脚本编译 (`Compiler`):**  提供了编译 Frida JavaScript 脚本的功能，可以将脚本打包成更高效的形式。
5. **取消操作 (`Cancellable`):**  实现了一种取消长时间运行操作的机制，增强了程序的健壮性。
6. **认证回调处理 (`make_auth_callback`):**  为认证相关的回调函数提供便捷的封装。
7. **实用工具函数 (`_to_camel_case`):** 提供了一些辅助函数，例如将下划线命名转换为驼峰命名。

**与逆向方法的关联和举例说明：**

* **设备管理 (`DeviceManager`):** 在逆向分析中，首先需要确定目标进程运行在哪个设备上。`DeviceManager` 允许用户列举当前可用的设备 (`enumerate_devices`)，例如连接到 USB 的 Android 手机或者运行着 Frida Server 的远程主机。
    * **举例：** 逆向分析一个 Android 应用，用户需要先通过 USB 连接手机，然后使用 `DeviceManager.get_usb_device()` 获取代表该手机的 `Device` 对象，才能进一步操作该手机上的进程。
* **Portal 服务 (`PortalService`):**  在多人协作逆向分析场景中，可以使用 `PortalService` 创建一个通信通道，不同的分析人员可以通过这个通道交换信息、共享分析结果或同步操作。
    * **举例：** 两个逆向工程师正在分析同一个复杂的 Android 应用，他们可以各自连接到同一个 `PortalService`，并在发现关键代码片段或漏洞时，通过 `post()` 方法发送消息通知对方。
* **脚本编译 (`Compiler`):**  在开发复杂的 Frida 脚本时，可以使用 `Compiler` 将脚本编译成二进制形式，这可以提高脚本的执行效率，并可能降低被目标进程检测到的风险。
    * **举例：** 编写了一个用于 hook 多个函数并记录其参数和返回值的 Frida 脚本，为了提高执行效率，可以使用 `Compiler.build()` 将其编译后再注入到目标进程。

**涉及二进制底层、Linux/Android 内核及框架的知识和举例说明：**

* **设备类型和连接方式 (`Device`, `DeviceManager`):**  区分本地、远程和 USB 设备，涉及到操作系统对设备管理的抽象和 Frida Agent 的部署方式。例如，连接 USB 设备需要理解 ADB (Android Debug Bridge) 的工作原理，连接远程设备需要了解网络通信和 Frida Server 的部署。
* **进程操作 (`Device.attach`, `Device.spawn`):**  这些方法直接对应操作系统提供的进程管理 API，例如 Linux 的 `ptrace` 或 Android 的相应机制。Frida 底层需要与这些 API 交互才能实现进程的附加和启动。
* **信号处理 (`Device.on`, `Device.off`, `DeviceManager.on`, `DeviceManager.off`):**  Frida 使用信号机制来通知用户各种事件，例如进程崩溃 (`process-crashed`)、设备连接/断开 (`added`, `removed`) 等。这与操作系统的信号处理机制密切相关。
* **Portal 服务的网络通信 (`PortalService`, `EndpointParameters`):**  `PortalService` 的实现涉及到网络编程，需要处理 TCP 连接、数据序列化 (JSON) 等底层细节。`EndpointParameters` 中定义的地址和端口信息直接对应网络通信的配置。

**逻辑推理的假设输入与输出：**

* **`Device._pid_of(target: ProcessTarget)`:**
    * **假设输入 1:** `target` 为字符串 `"com.example.app"`，并且系统中存在名为 `com.example.app` 的进程，其 PID 为 1234。
    * **输出 1:** `1234`
    * **假设输入 2:** `target` 为整数 `5678`。
    * **输出 2:** `5678`
    * **假设输入 3:** `target` 为字符串 `"nonexistent_app"`，并且系统中不存在名为 `nonexistent_app` 的进程。
    * **输出 3:** 抛出异常，因为 `self.get_process(target)` 会失败。
* **`DeviceManager.get_device_matching(predicate, timeout)`:**
    * **假设输入:** `predicate` 是一个 lambda 函数 `lambda d: d.type == "usb"`，`timeout` 为 5。系统中存在一个 USB 设备。
    * **输出:** 返回代表该 USB 设备的 `Device` 对象。
    * **假设输入:** `predicate` 是一个 lambda 函数 `lambda d: d.id == "invalid_id"`，`timeout` 为 2。系统中没有 ID 为 `"invalid_id"` 的设备。
    * **输出:** 在 `timeout` 时间到达后抛出超时异常。

**涉及用户或编程常见的使用错误和举例说明：**

* **`Device.attach(target)`:**
    * **错误：** 尝试附加到一个不存在的进程名或 PID。
    * **举例：** `device.attach("nonexistent_process")` 或 `device.attach(99999)` (假设系统中没有 PID 为 99999 的进程)。这将导致 Frida 抛出异常。
* **`DeviceManager.get_device(id)`:**
    * **错误：** 使用错误的设备 ID。
    * **举例：** 用户错误地记住了设备的 ID，使用 `device_manager.get_device("wrong_device_id")`，这将返回 `None` 或者在设置了超时的情况下抛出异常。
* **`PortalService.post(connection_id, message)`:**
    * **错误：** 向一个不存在的 `connection_id` 发送消息。
    * **举例：** 在客户端断开连接后，服务端仍然尝试使用之前的 `connection_id` 发送消息，会导致发送失败。
* **信号处理 (`on`, `off`):**
    * **错误：**  忘记调用 `off` 来移除不再需要的信号处理函数，可能导致内存泄漏或意外的行为。
    * **举例：**  在完成某个操作后，仍然保留着对 `process-crashed` 信号的处理函数，即使不再需要监听进程崩溃事件。

**用户操作是如何一步步的到达这里，作为调试线索：**

一个典型的 Frida 使用流程，可能会逐步涉及到这里定义的类和方法：

1. **导入 Frida 库：** 用户首先会在 Python 脚本中导入 `frida` 库。
2. **获取设备管理器：** 使用 `frida.get_device_manager()` 获取 `DeviceManager` 的实例。
3. **列举或选择设备：** 用户可能调用 `device_manager.enumerate_devices()` 查看可用设备，或者使用 `device_manager.get_usb_device()`、`device_manager.get_remote_device()` 或 `device_manager.get_device(id)` 来获取目标 `Device` 对象。
4. **附加或启动进程：**  用户使用获取到的 `Device` 对象调用 `device.attach(target)` 或 `device.spawn(program)` 来连接到目标进程。
5. **加载或注入脚本：**  用户可能会创建一个 `frida.Script` 对象并调用 `session.create_script()`，或者使用 `device.inject_library()` 注入自定义的 native 库。
6. **监听设备事件：** 为了监控目标设备的状态，用户可能会使用 `device.on()` 注册信号处理函数，例如监听进程崩溃事件。
7. **使用 Portal 服务（可选）：** 如果需要客户端之间的通信，用户可能会创建一个 `PortalService` 实例并启动它。
8. **编译脚本（可选）：** 对于复杂的脚本，用户可能会使用 `Compiler` 类来编译脚本。
9. **处理异步操作：**  在进行一些可能耗时的操作时，Frida 内部会使用 `Cancellable` 来支持取消操作。

当用户在使用 Frida 进行动态分析时遇到问题，例如无法连接设备、附加进程失败、脚本注入失败等，调试过程可能会涉及到检查 `DeviceManager` 返回的设备列表、`Device` 对象的连接状态、以及可能出现的信号事件等。因此，理解这些核心类的功能和交互方式对于调试 Frida 脚本至关重要。

总而言之，这部分代码继续构建了 Frida 框架的核心能力，提供了设备管理、远程连接、Portal 服务、脚本编译和取消操作等关键功能，这些功能是 Frida 进行动态插桩和逆向分析的基础。理解这些组件的工作原理，有助于用户更有效地使用 Frida 进行安全研究、漏洞分析和软件调试等工作。

Prompt: 
```
这是目录为frida/subprojects/frida-python/frida/core.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
f(self, signal: Literal["process-crashed"], callback: DeviceProcessCrashedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["output"], callback: DeviceOutputCallback) -> None: ...

    @overload
    def off(self, signal: Literal["uninjected"], callback: DeviceUninjectedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["lost"], callback: DeviceLostCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)

    def _pid_of(self, target: ProcessTarget) -> int:
        if isinstance(target, str):
            return self.get_process(target).pid
        else:
            return target


DeviceManagerAddedCallback = Callable[[_frida.Device], None]
DeviceManagerRemovedCallback = Callable[[_frida.Device], None]
DeviceManagerChangedCallback = Callable[[], None]


class DeviceManager:
    def __init__(self, impl: _frida.DeviceManager) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    def get_local_device(self) -> Device:
        """
        Get the local device
        """

        return self.get_device_matching(lambda d: d.type == "local", timeout=0)

    def get_remote_device(self) -> Device:
        """
        Get the first remote device in the devices list
        """

        return self.get_device_matching(lambda d: d.type == "remote", timeout=0)

    def get_usb_device(self, timeout: int = 0) -> Device:
        """
        Get the first device connected over USB in the devices list
        """

        return self.get_device_matching(lambda d: d.type == "usb", timeout)

    def get_device(self, id: Optional[str], timeout: int = 0) -> Device:
        """
        Get a device by its id
        """

        return self.get_device_matching(lambda d: d.id == id, timeout)

    @cancellable
    def get_device_matching(self, predicate: Callable[[Device], bool], timeout: int = 0) -> Device:
        """
        Get device matching predicate
        :param predicate: a function to filter the devices
        :param timeout: operation timeout in seconds
        """

        if timeout < 0:
            raw_timeout = -1
        elif timeout == 0:
            raw_timeout = 0
        else:
            raw_timeout = int(timeout * 1000.0)
        return Device(self._impl.get_device_matching(lambda d: predicate(Device(d)), raw_timeout))

    @cancellable
    def enumerate_devices(self) -> List[Device]:
        """
        Enumerate devices
        """

        return [Device(device) for device in self._impl.enumerate_devices()]

    @cancellable
    def add_remote_device(
        self,
        address: str,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        token: Optional[str] = None,
        keepalive_interval: Optional[int] = None,
    ) -> Device:
        """
        Add a remote device
        """

        kwargs: Dict[str, Any] = {
            "certificate": certificate,
            "origin": origin,
            "token": token,
            "keepalive_interval": keepalive_interval,
        }
        _filter_missing_kwargs(kwargs)
        return Device(self._impl.add_remote_device(address, **kwargs))

    @cancellable
    def remove_remote_device(self, address: str) -> None:
        """
        Remove a remote device
        """

        self._impl.remove_remote_device(address=address)

    @overload
    def on(self, signal: Literal["added"], callback: DeviceManagerAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["removed"], callback: DeviceManagerRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["changed"], callback: DeviceManagerChangedCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["added"], callback: DeviceManagerAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["removed"], callback: DeviceManagerRemovedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["changed"], callback: DeviceManagerChangedCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


class EndpointParameters:
    def __init__(
        self,
        address: Optional[str] = None,
        port: Optional[int] = None,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        authentication: Optional[Tuple[str, Union[str, Callable[[str], Any]]]] = None,
        asset_root: Optional[str] = None,
    ):
        kwargs: Dict[str, Any] = {"address": address, "port": port, "certificate": certificate, "origin": origin}
        if asset_root is not None:
            kwargs["asset_root"] = str(asset_root)
        _filter_missing_kwargs(kwargs)

        if authentication is not None:
            (auth_scheme, auth_data) = authentication
            if auth_scheme == "token":
                kwargs["auth_token"] = auth_data
            elif auth_scheme == "callback":
                if not callable(auth_data):
                    raise ValueError(
                        "Authentication data must provide a Callable if the authentication scheme is callback"
                    )
                kwargs["auth_callback"] = make_auth_callback(auth_data)
            else:
                raise ValueError("invalid authentication scheme")

        self._impl = _frida.EndpointParameters(**kwargs)


PortalServiceNodeJoinedCallback = Callable[[int, _frida.Application], None]
PortalServiceNodeLeftCallback = Callable[[int, _frida.Application], None]
PortalServiceNodeConnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceNodeDisconnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceControllerConnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceControllerDisconnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceAuthenticatedCallback = Callable[[int, Mapping[Any, Any]], None]
PortalServiceSubscribeCallback = Callable[[int], None]
PortalServiceMessageCallback = Callable[[int, Mapping[Any, Any], Optional[bytes]], None]


class PortalService:
    def __init__(
        self,
        cluster_params: EndpointParameters = EndpointParameters(),
        control_params: Optional[EndpointParameters] = None,
    ) -> None:
        args = [cluster_params._impl]
        if control_params is not None:
            args.append(control_params._impl)
        impl = _frida.PortalService(*args)

        self.device = impl.device
        self._impl = impl
        self._on_authenticated_callbacks: List[PortalServiceAuthenticatedCallback] = []
        self._on_message_callbacks: List[PortalServiceMessageCallback] = []

        impl.on("authenticated", self._on_authenticated)
        impl.on("message", self._on_message)

    @cancellable
    def start(self) -> None:
        """
        Start listening for incoming connections
        :raises InvalidOperationError: if the service isn't stopped
        :raises AddressInUseError: if the given address is already in use
        """

        self._impl.start()

    @cancellable
    def stop(self) -> None:
        """
        Stop listening for incoming connections, and kick any connected clients
        :raises InvalidOperationError: if the service is already stopped
        """

        self._impl.stop()

    def post(self, connection_id: int, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a message to a specific control channel.
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(connection_id, raw_message, **kwargs)

    def narrowcast(self, tag: str, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a message to control channels with a specific tag
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.narrowcast(tag, raw_message, **kwargs)

    def broadcast(self, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Broadcast a message to all control channels
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.broadcast(raw_message, **kwargs)

    def enumerate_tags(self, connection_id: int) -> List[str]:
        """
        Enumerate tags of a specific connection
        """

        return self._impl.enumerate_tags(connection_id)

    def tag(self, connection_id: int, tag: str) -> None:
        """
        Tag a specific control channel
        """

        self._impl.tag(connection_id, tag)

    def untag(self, connection_id: int, tag: str) -> None:
        """
        Untag a specific control channel
        """

        self._impl.untag(connection_id, tag)

    @overload
    def on(self, signal: Literal["node-joined"], callback: PortalServiceNodeJoinedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["node-left"], callback: PortalServiceNodeLeftCallback) -> None: ...

    @overload
    def on(
        self, signal: Literal["controller-connected"], callback: PortalServiceControllerConnectedCallback
    ) -> None: ...

    @overload
    def on(
        self, signal: Literal["controller-disconnected"], callback: PortalServiceControllerDisconnectedCallback
    ) -> None: ...

    @overload
    def on(self, signal: Literal["node-connected"], callback: PortalServiceNodeConnectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["node-disconnected"], callback: PortalServiceNodeDisconnectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["authenticated"], callback: PortalServiceAuthenticatedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["subscribe"], callback: PortalServiceSubscribeCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: PortalServiceMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "authenticated":
            self._on_authenticated_callbacks.append(callback)
        elif signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "authenticated":
            self._on_authenticated_callbacks.remove(callback)
        elif signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def _on_authenticated(self, connection_id: int, raw_session_info: str) -> None:
        session_info = json.loads(raw_session_info)

        for callback in self._on_authenticated_callbacks[:]:
            try:
                callback(connection_id, session_info)
            except:
                traceback.print_exc()

    def _on_message(self, connection_id: int, raw_message: str, data: Optional[bytes]) -> None:
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(connection_id, message, data)
            except:
                traceback.print_exc()


class CompilerDiagnosticFile(TypedDict):
    path: str
    line: int
    character: int


class CompilerDiagnostic(TypedDict):
    category: str
    code: int
    file: NotRequired[CompilerDiagnosticFile]
    text: str


CompilerStartingCallback = Callable[[], None]
CompilerFinishedCallback = Callable[[], None]
CompilerOutputCallback = Callable[[str], None]
CompilerDiagnosticsCallback = Callable[[List[CompilerDiagnostic]], None]


class Compiler:
    def __init__(self) -> None:
        self._impl = _frida.Compiler(get_device_manager()._impl)

    def __repr__(self) -> str:
        return repr(self._impl)

    @cancellable
    def build(
        self,
        entrypoint: str,
        project_root: Optional[str] = None,
        source_maps: Optional[str] = None,
        compression: Optional[str] = None,
    ) -> str:
        kwargs = {"project_root": project_root, "source_maps": source_maps, "compression": compression}
        _filter_missing_kwargs(kwargs)
        return self._impl.build(entrypoint, **kwargs)

    @cancellable
    def watch(
        self,
        entrypoint: str,
        project_root: Optional[str] = None,
        source_maps: Optional[str] = None,
        compression: Optional[str] = None,
    ) -> None:
        kwargs = {"project_root": project_root, "source_maps": source_maps, "compression": compression}
        _filter_missing_kwargs(kwargs)
        return self._impl.watch(entrypoint, **kwargs)

    @overload
    def on(self, signal: Literal["starting"], callback: CompilerStartingCallback) -> None: ...

    @overload
    def on(self, signal: Literal["finished"], callback: CompilerFinishedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["output"], callback: CompilerOutputCallback) -> None: ...

    @overload
    def on(self, signal: Literal["diagnostics"], callback: CompilerDiagnosticsCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["starting"], callback: CompilerStartingCallback) -> None: ...

    @overload
    def off(self, signal: Literal["finished"], callback: CompilerFinishedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["output"], callback: CompilerOutputCallback) -> None: ...

    @overload
    def off(self, signal: Literal["diagnostics"], callback: CompilerDiagnosticsCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.off(signal, callback)


class CancellablePollFD:
    def __init__(self, cancellable: _Cancellable) -> None:
        self.handle = cancellable.get_fd()
        self._cancellable: Optional[_Cancellable] = cancellable

    def __del__(self) -> None:
        self.release()

    def release(self) -> None:
        if self._cancellable is not None:
            if self.handle != -1:
                self._cancellable.release_fd()
                self.handle = -1
            self._cancellable = None

    def __repr__(self) -> str:
        return repr(self.handle)

    def __enter__(self) -> int:
        return self.handle

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        trace: Optional[TracebackType],
    ) -> None:
        self.release()


class Cancellable:
    def __init__(self) -> None:
        self._impl = _Cancellable()

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_cancelled(self) -> bool:
        """
        Query whether cancellable has been cancelled
        """

        return self._impl.is_cancelled()

    def raise_if_cancelled(self) -> None:
        """
        Raise an exception if cancelled
        :raises OperationCancelledError:
        """

        self._impl.raise_if_cancelled()

    def get_pollfd(self) -> CancellablePollFD:
        return CancellablePollFD(self._impl)

    @classmethod
    def get_current(cls) -> _frida.Cancellable:
        """
        Get the top cancellable from the stack
        """

        return _Cancellable.get_current()

    def __enter__(self) -> None:
        self._impl.push_current()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        trace: Optional[TracebackType],
    ) -> None:
        self._impl.pop_current()

    def connect(self, callback: Callable[..., Any]) -> int:
        """
        Register notification callback
        :returns: the created handler id
        """

        return self._impl.connect(callback)

    def disconnect(self, handler_id: int) -> None:
        """
        Unregister notification callback.
        """

        self._impl.disconnect(handler_id)

    def cancel(self) -> None:
        """
        Set cancellable to cancelled
        """

        self._impl.cancel()


def make_auth_callback(callback: Callable[[str], Any]) -> Callable[[Any], str]:
    """
    Wraps authenticated callbacks with JSON marshaling
    """

    def authenticate(token: str) -> str:
        session_info = callback(token)
        return json.dumps(session_info)

    return authenticate


def _to_camel_case(name: str) -> str:
    result = ""
    uppercase_next = False
    for c in name:
        if c == "_":
            uppercase_next = True
        elif uppercase_next:
            result += c.upper()
            uppercase_next = False
        else:
            result += c.lower()
    return result

"""


```