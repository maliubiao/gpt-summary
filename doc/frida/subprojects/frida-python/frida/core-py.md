Response:
The user wants a summary of the functionalities of the Python code provided, specifically focusing on its relevance to reverse engineering, interaction with low-level systems (Linux/Android kernel, etc.), logical reasoning aspects, potential user errors, and how a user might reach this code during debugging.

**Plan:**

1. **High-level overview:**  Summarize the core purpose of the `core.py` file within the Frida framework.
2. **Functionality breakdown:** Go through the major classes and functions, explaining their roles.
3. **Reverse engineering relevance:** Identify features directly used in reverse engineering tasks and provide concrete examples.
4. **Low-level interaction:**  Point out parts of the code that interact with or are relevant to OS kernels, frameworks (like Android's), and binary manipulation.
5. **Logical reasoning:** Analyze sections with conditional logic and provide hypothetical inputs and outputs.
6. **User errors:**  Identify common mistakes users might make when using the functionalities defined in this file.
7. **Debugging context:** Explain how a user might end up in this specific file while debugging Frida.
8. **Concise summary:**  Provide a final, brief overview of the file's purpose.
这是 Frida 动态 instrumentation 工具的 Python 核心模块 `core.py` 的源代码。它定义了 Frida Python API 中用于与 Frida Agent 交互的核心类和函数。以下是其功能的归纳：

**核心功能归纳：**

1. **设备管理 (Device Management):**
   - 提供了 `DeviceManager` 类（通过 `get_device_manager()` 获取），用于管理连接到 Frida 的设备（例如，本地计算机、远程设备、模拟器）。
   - 允许枚举和操作设备上的进程和应用。

2. **会话管理 (Session Management):**
   - 提供了 `Session` 类，表示与目标进程的连接会话。
   - 允许创建、附加和分离会话。
   - 支持子进程网关（child gating）。
   - 提供了创建和管理脚本的功能。

3. **脚本管理 (Script Management):**
   - 提供了 `Script` 类，代表注入到目标进程中的 JavaScript 代码。
   - 允许加载、卸载、永久化脚本。
   - 支持与脚本进行双向通信（通过 `post()` 发送消息，通过 `on('message')` 接收消息）。
   - 实现了远程过程调用 (RPC) 机制，允许 Python 代码调用脚本中导出的函数，反之亦然。
   - 提供了同步 (`exports_sync`) 和异步 (`exports_async`) 两种方式调用脚本导出的函数。
   - 支持启用和禁用脚本调试器。
   - 提供了设置脚本日志处理器的功能。

4. **RPC 支持 (Remote Procedure Call):**
   - `ScriptExportsSync` 和 `ScriptExportsAsync` 类作为代理对象，允许通过属性访问的方式调用脚本导出的函数。
   - `make_rpc_call_request()` 函数用于构建 RPC 请求。
   - `RPCException` 类用于封装脚本抛出的远程错误。

5. **消息总线 (Message Bus):**
   - 提供了 `Bus` 类，用于设备级别的消息通信。
   - 允许连接到消息总线 (`attach()`)，并发送 (`post()`) 和接收 (`on('message')`) 消息。

6. **IO 流 (IO Stream):**
   - 提供了 `IOStream` 类，用于与 Frida Agent 建立自定义的输入/输出流通道。

7. **服务 (Service):**
   - 提供了 `Service` 类，用于与设备上的特定服务进行交互。

8. **进程操作 (Process Operations):**
   - `Device` 类提供了 `spawn()` 用于启动新的进程，`input()` 用于向进程输入数据，`resume()` 用于恢复进程执行，`kill()` 用于终止进程。

9. **库注入 (Library Injection):**
   - `Device` 类提供了 `inject_library_file()` 和 `inject_library_blob()` 用于将动态链接库注入到目标进程。

10. **信号处理 (Signal Handling):**
    - 许多类（如 `Script`, `Session`, `Bus`, `Device`) 都支持通过 `on()` 和 `off()` 方法注册和移除事件回调函数，用于异步处理来自 Frida Agent 的事件通知。

**与其他逆向方法的关系：**

* **动态分析：**  `frida.core.py` 的核心功能是动态 instrumentation，这本身就是一种动态逆向分析方法。通过 `Script` 类，逆向工程师可以将 JavaScript 代码注入到目标进程中，实时地观察和修改程序的行为。
    * **举例：** 使用 `Script` 的 `load()` 方法加载一段 JavaScript 代码，该代码 hook 了 `open()` 系统调用，并记录下所有被打开的文件路径。

* **Hooking 和代码注入：**  `Script` 的加载机制以及 `inject_library_file()` 和 `inject_library_blob()` 方法是实现 Hooking 和代码注入的关键。
    * **举例：** 使用 `Script` 注入一段 JavaScript 代码，该代码替换了目标函数的一部分指令，改变程序的执行流程。

* **运行时修改：** 通过 JavaScript API，逆向工程师可以在运行时修改内存中的数据、函数参数、返回值等。
    * **举例：**  使用 `Script` 修改游戏中用于验证用户购买行为的标志位，从而绕过购买验证。

* **观察程序行为：** 通过 Hooking 和日志记录，可以详细地观察程序在运行时的行为，例如函数调用栈、内存访问模式等。
    * **举例：** 使用 `Script` Hook 关键函数，并打印其参数和返回值，以便理解程序的执行逻辑。

**涉及二进制底层、Linux/Android 内核及框架的知识：**

* **进程和线程：** `Device` 类中的 `enumerate_processes()`, `get_process()`, `spawn()`, `kill()` 等方法直接操作系统的进程管理机制。在 Linux/Android 上，这涉及到与内核的交互，例如通过系统调用来创建、查询和终止进程。
    * **举例：** `device.spawn(['/bin/ls', '-l'])`  会调用 Linux 的 `fork()` 和 `execve()` 系统调用（或 Android 类似的机制）来创建一个新的进程。

* **内存管理：** Frida 的 Hooking 和代码注入机制需要在目标进程的内存空间中进行操作。这需要理解目标平台的内存布局、地址空间等概念。
    * **举例：**  JavaScript 代码中使用 `Memory.read*()` 和 `Memory.write*()` 函数直接读写进程内存。

* **动态链接库：** `inject_library_file()` 和 `inject_library_blob()` 方法涉及将动态链接库加载到目标进程，这需要理解目标平台的动态链接机制（例如 Linux 的 `dlopen()`）。
    * **举例：** `device.inject_library_file(pid, '/path/to/mylib.so', 'my_init', '')`  会在目标进程中加载 `/path/to/mylib.so`，并调用其 `my_init` 函数。

* **系统调用：**  虽然 `frida.core.py` 本身不直接涉及系统调用，但 Frida Agent 和注入的 JavaScript 代码经常会使用系统调用来实现 Hooking、内存访问等功能。

* **Android Framework：** 在 Android 逆向中，Frida 可以用来 Hook Java 层的 API，这需要理解 Android 的 ART 虚拟机和 Framework 的结构。
    * **举例：**  使用 Frida 的 JavaScript API Hook `android.app.Activity` 类的 `onCreate()` 方法。

**逻辑推理：**

* **`_filter_missing_kwargs(d: MutableMapping[Any, Any]) -> None`:**
    - **假设输入：** `kwargs = {'name': 'my_script', 'snapshot': None, 'runtime': 'v8'}`
    - **输出：** `kwargs` 将被修改为 `{'name': 'my_script', 'runtime': 'v8'}`，因为 `snapshot` 的值为 `None`，所以被移除了。
    - **解释：** 这个函数用于清理可选参数字典，移除值为 `None` 的键值对，避免将其传递给底层的 Frida C 接口。

* **`make_rpc_call_request(js_name: str, args: Sequence[Any]) -> Tuple[List[Any], Optional[bytes]]`:**
    - **假设输入：** `js_name = 'myMethod'`, `args = [1, 'hello', b'some data']`
    - **输出：** `(['call', 'myMethod', [1, 'hello']], b'some data')`
    - **解释：** 如果参数列表的最后一个元素是 `bytes` 类型，它会被作为单独的数据 payload 提取出来，RPC 请求的参数中不包含它。这允许传递二进制数据。

* **`Script._on_rpc_message(...)`:**
    - **假设输入：** `request_id = 123`, `operation = 'ok'`, `params = ['成功']`, `data = None`
    - **假设 `self._pending[123]` 存在，并且是一个回调函数。**
    - **输出：** `self._pending[123]` 这个回调函数会被调用，传入参数 `value = '成功'`, `error = None`。
    - **解释：** 这个函数处理来自脚本的 RPC 响应。如果操作是 'ok'，则调用对应的回调函数并传入结果值；如果是 'error'，则创建 `RPCException` 对象并传入。

**用户或编程常见的使用错误：**

* **忘记调用 `script.load()`:**  创建 `Script` 对象后，必须显式调用 `load()` 方法才能将脚本加载到目标进程。如果忘记调用，脚本不会执行。
    * **举例：**
      ```python
      session = frida.attach("target_app")
      script = session.create_script("console.log('Hello from Frida!');")
      # 错误：忘记调用 script.load()
      # 脚本不会执行
      ```

* **同步和异步调用混淆：**  Frida 提供了同步和异步两种 RPC 调用方式。如果需要在异步环境中使用同步调用，可能会导致阻塞。反之亦然。
    * **举例：** 在 `async` 函数中直接调用 `script.exports.my_sync_function()` 可能会导致 event loop 阻塞。应该使用 `await script.exports_async.my_sync_function()`.

* **错误处理不足：**  在进行 RPC 调用时，应该捕获 `RPCException` 以处理脚本中发生的错误。
    * **举例：**
      ```python
      try:
          result = script.exports.some_function()
      except frida.RPCException as e:
          print(f"脚本发生错误: {e}")
      ```

* **不正确的参数类型：**  传递给脚本导出函数的参数类型必须与脚本中定义的类型一致，否则会导致 RPC 调用失败。

* **在脚本销毁后尝试调用 RPC：** 如果脚本已经被卸载或销毁，尝试调用其导出的函数会抛出异常。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **安装 Frida 和 Frida Python 绑定：** 用户首先需要安装 Frida 和 `frida` Python 包。
2. **编写 Python 脚本使用 Frida API：** 用户编写一个 Python 脚本，导入 `frida` 模块，并使用其中的类和函数来连接设备、附加进程、创建和加载脚本等。
   ```python
   import frida

   device = frida.get_usb_device()
   pid = device.spawn(["com.example.targetapp"])
   session = device.attach(pid)
   script = session.create_script("console.log('Hello');")
   script.load()
   ```
3. **运行 Python 脚本：**  用户执行编写的 Python 脚本。
4. **遇到问题或需要深入理解 Frida 的行为：** 在使用 Frida 的过程中，用户可能会遇到各种问题，例如脚本没有按预期工作、连接失败、出现异常等。为了调试这些问题，用户可能需要查看 Frida Python 绑定的源代码。
5. **设置断点或打印语句：**  用户可能会在 `frida/core.py` 文件中设置断点，或者添加 `print()` 语句来跟踪代码的执行流程，例如查看某个变量的值、函数的调用顺序等。
6. **查看调用堆栈：** 当程序抛出异常时，用户可以查看调用堆栈，从而定位到 `frida/core.py` 文件中的特定行。例如，如果 RPC 调用失败，用户可能会在堆栈信息中看到与 `Script._rpc_request` 或 `Script._on_rpc_message` 相关的调用。
7. **查阅文档或源代码：**  为了理解某个 Frida API 的工作原理，用户可能会直接查看 `frida/core.py` 中的源代码，例如查看 `Session.create_script()` 方法是如何创建 `Script` 对象的。

总而言之，`frida/core.py` 是 Frida Python 绑定的核心，它封装了与 Frida Agent 通信的底层细节，并提供了用户友好的 Python API，用于实现动态 instrumentation 的各种功能。理解这个文件的功能对于深入使用 Frida 进行逆向分析至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/frida/core.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import functools
import json
import sys
import threading
import traceback
import warnings
from types import TracebackType
from typing import (
    Any,
    AnyStr,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired

from . import _frida

_device_manager = None

_Cancellable = _frida.Cancellable

ProcessTarget = Union[int, str]
Spawn = _frida.Spawn


@dataclasses.dataclass
class RPCResult:
    finished: bool = False
    value: Any = None
    error: Optional[Exception] = None


def get_device_manager() -> "DeviceManager":
    """
    Get or create a singleton DeviceManager that let you manage all the devices
    """

    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager(_frida.DeviceManager())
    return _device_manager


def _filter_missing_kwargs(d: MutableMapping[Any, Any]) -> None:
    for key in list(d.keys()):
        if d[key] is None:
            d.pop(key)


R = TypeVar("R")


def cancellable(f: Callable[..., R]) -> Callable[..., R]:
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> R:
        cancellable = kwargs.pop("cancellable", None)
        if cancellable is not None:
            with cancellable:
                return f(*args, **kwargs)

        return f(*args, **kwargs)

    return wrapper


class IOStream:
    """
    Frida's own implementation of an input/output stream
    """

    def __init__(self, impl: _frida.IOStream) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_closed(self) -> bool:
        """
        Query whether the stream is closed
        """

        return self._impl.is_closed()

    @cancellable
    def close(self) -> None:
        """
        Close the stream.
        """

        self._impl.close()

    @cancellable
    def read(self, count: int) -> bytes:
        """
        Read up to the specified number of bytes from the stream
        """

        return self._impl.read(count)

    @cancellable
    def read_all(self, count: int) -> bytes:
        """
        Read exactly the specified number of bytes from the stream
        """

        return self._impl.read_all(count)

    @cancellable
    def write(self, data: bytes) -> int:
        """
        Write as much as possible of the provided data to the stream
        """

        return self._impl.write(data)

    @cancellable
    def write_all(self, data: bytes) -> None:
        """
        Write all of the provided data to the stream
        """

        self._impl.write_all(data)


class PortalMembership:
    def __init__(self, impl: _frida.PortalMembership) -> None:
        self._impl = impl

    @cancellable
    def terminate(self) -> None:
        """
        Terminate the membership
        """

        self._impl.terminate()


class ScriptExportsSync:
    """
    Proxy object that expose all the RPC exports of a script as attributes on this class

    A method named exampleMethod in a script will be called with instance.example_method on this object
    """

    def __init__(self, script: "Script") -> None:
        self._script = script

    def __getattr__(self, name: str) -> Callable[..., Any]:
        script = self._script
        js_name = _to_camel_case(name)

        def method(*args: Any, **kwargs: Any) -> Any:
            request, data = make_rpc_call_request(js_name, args)
            return script._rpc_request(request, data, **kwargs)

        return method

    def __dir__(self) -> List[str]:
        return self._script.list_exports_sync()


ScriptExports = ScriptExportsSync


class ScriptExportsAsync:
    """
    Proxy object that expose all the RPC exports of a script as attributes on this class

    A method named exampleMethod in a script will be called with instance.example_method on this object
    """

    def __init__(self, script: "Script") -> None:
        self._script = script

    def __getattr__(self, name: str) -> Callable[..., Awaitable[Any]]:
        script = self._script
        js_name = _to_camel_case(name)

        async def method(*args: Any, **kwargs: Any) -> Any:
            request, data = make_rpc_call_request(js_name, args)
            return await script._rpc_request_async(request, data, **kwargs)

        return method

    def __dir__(self) -> List[str]:
        return self._script.list_exports_sync()


def make_rpc_call_request(js_name: str, args: Sequence[Any]) -> Tuple[List[Any], Optional[bytes]]:
    if args and isinstance(args[-1], bytes):
        raw_args = args[:-1]
        data = args[-1]
    else:
        raw_args = args
        data = None
    return (["call", js_name, raw_args], data)


class ScriptErrorMessage(TypedDict):
    type: Literal["error"]
    description: str
    stack: NotRequired[str]
    fileName: NotRequired[str]
    lineNumber: NotRequired[int]
    columnNumber: NotRequired[int]


class ScriptPayloadMessage(TypedDict):
    type: Literal["send"]
    payload: NotRequired[Any]


ScriptMessage = Union[ScriptPayloadMessage, ScriptErrorMessage]
ScriptMessageCallback = Callable[[ScriptMessage, Optional[bytes]], None]
ScriptDestroyedCallback = Callable[[], None]


class RPCException(Exception):
    """
    Wraps remote errors from the script RPC
    """

    def __str__(self) -> str:
        return str(self.args[2]) if len(self.args) >= 3 else str(self.args[0])


class Script:
    def __init__(self, impl: _frida.Script) -> None:
        self.exports_sync = ScriptExportsSync(self)
        self.exports_async = ScriptExportsAsync(self)

        self._impl = impl

        self._on_message_callbacks: List[ScriptMessageCallback] = []
        self._log_handler: Callable[[str, str], None] = self.default_log_handler

        self._pending: Dict[
            int, Callable[[Optional[Any], Optional[Union[RPCException, _frida.InvalidOperationError]]], None]
        ] = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

        impl.on("destroyed", self._on_destroyed)
        impl.on("message", self._on_message)

    @property
    def exports(self) -> ScriptExportsSync:
        """
        The old way of retrieving the synchronous exports caller
        """

        warnings.warn(
            "Script.exports will become asynchronous in the future, use the explicit Script.exports_sync instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.exports_sync

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_destroyed(self) -> bool:
        """
        Query whether the script has been destroyed
        """

        return self._impl.is_destroyed()

    @cancellable
    def load(self) -> None:
        """
        Load the script.
        """

        self._impl.load()

    @cancellable
    def unload(self) -> None:
        """
        Unload the script
        """

        self._impl.unload()

    @cancellable
    def eternalize(self) -> None:
        """
        Eternalize the script
        """

        self._impl.eternalize()

    def post(self, message: Any, data: Optional[AnyStr] = None) -> None:
        """
        Post a JSON-encoded message to the script
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(raw_message, **kwargs)

    @cancellable
    def enable_debugger(self, port: Optional[int] = None) -> None:
        """
        Enable the Node.js compatible script debugger
        """

        kwargs = {"port": port}
        _filter_missing_kwargs(kwargs)
        self._impl.enable_debugger(**kwargs)

    @cancellable
    def disable_debugger(self) -> None:
        """
        Disable the Node.js compatible script debugger
        """

        self._impl.disable_debugger()

    @overload
    def on(self, signal: Literal["destroyed"], callback: ScriptDestroyedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: ScriptMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["destroyed"], callback: ScriptDestroyedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: ScriptMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def get_log_handler(self) -> Callable[[str, str], None]:
        """
        Get the method that handles the script logs
        """

        return self._log_handler

    def set_log_handler(self, handler: Callable[[str, str], None]) -> None:
        """
        Set the method that handles the script logs
        :param handler: a callable that accepts two parameters:
                        1. the log level name
                        2. the log message
        """

        self._log_handler = handler

    def default_log_handler(self, level: str, text: str) -> None:
        """
        The default implementation of the log handler, prints the message to stdout
        or stderr, depending on the level
        """

        if level == "info":
            print(text, file=sys.stdout)
        else:
            print(text, file=sys.stderr)

    async def list_exports_async(self) -> List[str]:
        """
        Asynchronously list all the exported attributes from the script's rpc
        """

        result = await self._rpc_request_async(["list"])
        assert isinstance(result, list)
        return result

    def list_exports_sync(self) -> List[str]:
        """
        List all the exported attributes from the script's rpc
        """

        result = self._rpc_request(["list"])
        assert isinstance(result, list)
        return result

    def list_exports(self) -> List[str]:
        """
        List all the exported attributes from the script's rpc
        """

        warnings.warn(
            "Script.list_exports will become asynchronous in the future, use the explicit Script.list_exports_sync instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.list_exports_sync()

    def _rpc_request_async(self, args: Any, data: Optional[bytes] = None) -> asyncio.Future[Any]:
        loop = asyncio.get_event_loop()
        future: asyncio.Future[Any] = asyncio.Future()

        def on_complete(value: Any, error: Optional[Union[RPCException, _frida.InvalidOperationError]]) -> None:
            if error is not None:
                loop.call_soon_threadsafe(future.set_exception, error)
            else:
                loop.call_soon_threadsafe(future.set_result, value)

        request_id = self._append_pending(on_complete)

        if not self.is_destroyed:
            self._send_rpc_call(request_id, args, data)
        else:
            self._on_destroyed()

        return future

    @cancellable
    def _rpc_request(self, args: Any, data: Optional[bytes] = None) -> Any:
        result = RPCResult()

        def on_complete(value: Any, error: Optional[Union[RPCException, _frida.InvalidOperationError]]) -> None:
            with self._cond:
                result.finished = True
                result.value = value
                result.error = error
                self._cond.notify_all()

        def on_cancelled() -> None:
            self._pending.pop(request_id, None)
            on_complete(None, None)

        request_id = self._append_pending(on_complete)

        if not self.is_destroyed:
            self._send_rpc_call(request_id, args, data)

            cancellable = Cancellable.get_current()
            cancel_handler = cancellable.connect(on_cancelled)
            try:
                with self._cond:
                    while not result.finished:
                        self._cond.wait()
            finally:
                cancellable.disconnect(cancel_handler)

            cancellable.raise_if_cancelled()
        else:
            self._on_destroyed()

        if result.error is not None:
            raise result.error

        return result.value

    def _append_pending(
        self, callback: Callable[[Any, Optional[Union[RPCException, _frida.InvalidOperationError]]], None]
    ) -> int:
        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = callback
        return request_id

    def _send_rpc_call(self, request_id: int, args: Any, data: Optional[bytes]) -> None:
        self.post(["frida:rpc", request_id, *args], data)

    def _on_rpc_message(self, request_id: int, operation: str, params: List[Any], data: Optional[Any]) -> None:
        if operation in ("ok", "error"):
            callback = self._pending.pop(request_id, None)
            if callback is None:
                return

            value = None
            error = None
            if operation == "ok":
                if data is not None:
                    value = (params[1], data) if len(params) > 1 else data
                else:
                    value = params[0]
            else:
                error = RPCException(*params[0:3])

            callback(value, error)

    def _on_destroyed(self) -> None:
        while True:
            next_pending = None

            with self._cond:
                pending_ids = list(self._pending.keys())
                if len(pending_ids) > 0:
                    next_pending = self._pending.pop(pending_ids[0])

            if next_pending is None:
                break

            next_pending(None, _frida.InvalidOperationError("script has been destroyed"))

    def _on_message(self, raw_message: str, data: Optional[bytes]) -> None:
        message = json.loads(raw_message)

        mtype = message["type"]
        payload = message.get("payload", None)
        if mtype == "log":
            level = message["level"]
            text = payload
            self._log_handler(level, text)
        elif mtype == "send" and isinstance(payload, list) and len(payload) > 0 and payload[0] == "frida:rpc":
            request_id = payload[1]
            operation = payload[2]
            params = payload[3:]
            self._on_rpc_message(request_id, operation, params, data)
        else:
            for callback in self._on_message_callbacks[:]:
                try:
                    callback(message, data)
                except:
                    traceback.print_exc()


SessionDetachedCallback = Callable[
    [
        Literal[
            "application-requested", "process-replaced", "process-terminated", "connection-terminated", "device-lost"
        ],
        Optional[_frida.Crash],
    ],
    None,
]


class Session:
    def __init__(self, impl: _frida.Session) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_detached(self) -> bool:
        """
        Query whether the session is detached
        """

        return self._impl.is_detached()

    @cancellable
    def detach(self) -> None:
        """
        Detach session from the process
        """

        self._impl.detach()

    @cancellable
    def resume(self) -> None:
        """
        Resume session after network error
        """

        self._impl.resume()

    @cancellable
    def enable_child_gating(self) -> None:
        """
        Enable child gating
        """

        self._impl.enable_child_gating()

    @cancellable
    def disable_child_gating(self) -> None:
        """
        Disable child gating
        """

        self._impl.disable_child_gating()

    @cancellable
    def create_script(
        self, source: str, name: Optional[str] = None, snapshot: Optional[bytes] = None, runtime: Optional[str] = None
    ) -> Script:
        """
        Create a new script
        """

        kwargs = {"name": name, "snapshot": snapshot, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return Script(self._impl.create_script(source, **kwargs))  # type: ignore

    @cancellable
    def create_script_from_bytes(
        self, data: bytes, name: Optional[str] = None, snapshot: Optional[bytes] = None, runtime: Optional[str] = None
    ) -> Script:
        """
        Create a new script from bytecode
        """

        kwargs = {"name": name, "snapshot": snapshot, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return Script(self._impl.create_script_from_bytes(data, **kwargs))  # type: ignore

    @cancellable
    def compile_script(self, source: str, name: Optional[str] = None, runtime: Optional[str] = None) -> bytes:
        """
        Compile script source code to bytecode
        """

        kwargs = {"name": name, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return self._impl.compile_script(source, **kwargs)

    @cancellable
    def snapshot_script(self, embed_script: str, warmup_script: Optional[str], runtime: Optional[str] = None) -> bytes:
        """
        Evaluate script and snapshot the resulting VM state
        """
        kwargs = {"warmup_script": warmup_script, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return self._impl.snapshot_script(embed_script, **kwargs)

    @cancellable
    def setup_peer_connection(
        self, stun_server: Optional[str] = None, relays: Optional[Sequence[_frida.Relay]] = None
    ) -> None:
        """
        Set up a peer connection with the target process
        """

        kwargs = {"stun_server": stun_server, "relays": relays}
        _filter_missing_kwargs(kwargs)
        self._impl.setup_peer_connection(**kwargs)  # type: ignore

    @cancellable
    def join_portal(
        self,
        address: str,
        certificate: Optional[str] = None,
        token: Optional[str] = None,
        acl: Union[None, List[str], Tuple[str]] = None,
    ) -> PortalMembership:
        """
        Join a portal
        """

        kwargs: Dict[str, Any] = {"certificate": certificate, "token": token, "acl": acl}
        _filter_missing_kwargs(kwargs)
        return PortalMembership(self._impl.join_portal(address, **kwargs))

    @overload
    def on(
        self,
        signal: Literal["detached"],
        callback: SessionDetachedCallback,
    ) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(
        self,
        signal: Literal["detached"],
        callback: SessionDetachedCallback,
    ) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


BusDetachedCallback = Callable[[], None]
BusMessageCallback = Callable[[Mapping[Any, Any], Optional[bytes]], None]


class Bus:
    def __init__(self, impl: _frida.Bus) -> None:
        self._impl = impl
        self._on_message_callbacks: List[Callable[..., Any]] = []

        impl.on("message", self._on_message)

    @cancellable
    def attach(self) -> None:
        """
        Attach to the bus
        """

        self._impl.attach()

    def post(self, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a JSON-encoded message to the bus
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(raw_message, **kwargs)

    @overload
    def on(self, signal: Literal["detached"], callback: BusDetachedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: BusMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["detached"], callback: BusDetachedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: BusMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def _on_message(self, raw_message: str, data: Any) -> None:
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(message, data)
            except:
                traceback.print_exc()


ServiceCloseCallback = Callable[[], None]
ServiceMessageCallback = Callable[[Any], None]


class Service:
    def __init__(self, impl: _frida.Service) -> None:
        self._impl = impl

    @cancellable
    def activate(self) -> None:
        """
        Activate the service
        """

        self._impl.activate()

    @cancellable
    def cancel(self) -> None:
        """
        Cancel the service
        """

        self._impl.cancel()

    def request(self, parameters: Any) -> Any:
        """
        Perform a request
        """

        return self._impl.request(parameters)

    @overload
    def on(self, signal: Literal["close"], callback: ServiceCloseCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: ServiceMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["close"], callback: ServiceCloseCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: ServiceMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


DeviceSpawnAddedCallback = Callable[[_frida.Spawn], None]
DeviceSpawnRemovedCallback = Callable[[_frida.Spawn], None]
DeviceChildAddedCallback = Callable[[_frida.Child], None]
DeviceChildRemovedCallback = Callable[[_frida.Child], None]
DeviceProcessCrashedCallback = Callable[[_frida.Crash], None]
DeviceOutputCallback = Callable[[int, int, bytes], None]
DeviceUninjectedCallback = Callable[[int], None]
DeviceLostCallback = Callable[[], None]


class Device:
    """
    Represents a device that Frida connects to
    """

    def __init__(self, device: _frida.Device) -> None:
        assert device.bus is not None
        self.id = device.id
        self.name = device.name
        self.icon = device.icon
        self.type = device.type
        self.bus = Bus(device.bus)

        self._impl = device

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_lost(self) -> bool:
        """
        Query whether the device has been lost
        """

        return self._impl.is_lost()

    @cancellable
    def query_system_parameters(self) -> Dict[str, Any]:
        """
        Returns a dictionary of information about the host system
        """

        return self._impl.query_system_parameters()

    @cancellable
    def get_frontmost_application(self, scope: Optional[str] = None) -> Optional[_frida.Application]:
        """
        Get details about the frontmost application
        """

        kwargs = {"scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.get_frontmost_application(**kwargs)

    @cancellable
    def enumerate_applications(
        self, identifiers: Optional[Sequence[str]] = None, scope: Optional[str] = None
    ) -> List[_frida.Application]:
        """
        Enumerate applications
        """

        kwargs = {"identifiers": identifiers, "scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.enumerate_applications(**kwargs)  # type: ignore

    @cancellable
    def enumerate_processes(
        self, pids: Optional[Sequence[int]] = None, scope: Optional[str] = None
    ) -> List[_frida.Process]:
        """
        Enumerate processes
        """

        kwargs = {"pids": pids, "scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.enumerate_processes(**kwargs)  # type: ignore

    @cancellable
    def get_process(self, process_name: str) -> _frida.Process:
        """
        Get the process with the given name
        :raises ProcessNotFoundError: if the process was not found or there were more than one process with the given name
        """

        process_name_lc = process_name.lower()
        matching = [
            process
            for process in self._impl.enumerate_processes()
            if fnmatch.fnmatchcase(process.name.lower(), process_name_lc)
        ]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            matches_list = ", ".join([f"{process.name} (pid: {process.pid})" for process in matching])
            raise _frida.ProcessNotFoundError(f"ambiguous name; it matches: {matches_list}")
        else:
            raise _frida.ProcessNotFoundError(f"unable to find process with name '{process_name}'")

    @cancellable
    def enable_spawn_gating(self) -> None:
        """
        Enable spawn gating
        """

        self._impl.enable_spawn_gating()

    @cancellable
    def disable_spawn_gating(self) -> None:
        """
        Disable spawn gating
        """

        self._impl.disable_spawn_gating()

    @cancellable
    def enumerate_pending_spawn(self) -> List[_frida.Spawn]:
        """
        Enumerate pending spawn
        """

        return self._impl.enumerate_pending_spawn()

    @cancellable
    def enumerate_pending_children(self) -> List[_frida.Child]:
        """
        Enumerate pending children
        """

        return self._impl.enumerate_pending_children()

    @cancellable
    def spawn(
        self,
        program: Union[str, List[Union[str, bytes]], Tuple[Union[str, bytes]]],
        argv: Union[None, List[Union[str, bytes]], Tuple[Union[str, bytes]]] = None,
        envp: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        stdio: Optional[str] = None,
        **kwargs: Any,
    ) -> int:
        """
        Spawn a process into an attachable state
        """

        if not isinstance(program, str):
            argv = program
            if isinstance(argv[0], bytes):
                program = argv[0].decode()
            else:
                program = argv[0]
            if len(argv) == 1:
                argv = None

        kwargs = {"argv": argv, "envp": envp, "env": env, "cwd": cwd, "stdio": stdio, "aux": kwargs}
        _filter_missing_kwargs(kwargs)
        return self._impl.spawn(program, **kwargs)

    @cancellable
    def input(self, target: ProcessTarget, data: bytes) -> None:
        """
        Input data on stdin of a spawned process
        :param target: the PID or name of the process
        """

        self._impl.input(self._pid_of(target), data)

    @cancellable
    def resume(self, target: ProcessTarget) -> None:
        """
        Resume a process from the attachable state
        :param target: the PID or name of the process
        """

        self._impl.resume(self._pid_of(target))

    @cancellable
    def kill(self, target: ProcessTarget) -> None:
        """
        Kill a process
        :param target: the PID or name of the process
        """
        self._impl.kill(self._pid_of(target))

    @cancellable
    def attach(
        self,
        target: ProcessTarget,
        realm: Optional[str] = None,
        persist_timeout: Optional[int] = None,
    ) -> Session:
        """
        Attach to a process
        :param target: the PID or name of the process
        """

        kwargs = {"realm": realm, "persist_timeout": persist_timeout}
        _filter_missing_kwargs(kwargs)
        return Session(self._impl.attach(self._pid_of(target), **kwargs))  # type: ignore

    @cancellable
    def inject_library_file(self, target: ProcessTarget, path: str, entrypoint: str, data: str) -> int:
        """
        Inject a library file to a process
        :param target: the PID or name of the process
        """

        return self._impl.inject_library_file(self._pid_of(target), path, entrypoint, data)

    @cancellable
    def inject_library_blob(self, target: ProcessTarget, blob: bytes, entrypoint: str, data: str) -> int:
        """
        Inject a library blob to a process
        :param target: the PID or name of the process
        """

        return self._impl.inject_library_blob(self._pid_of(target), blob, entrypoint, data)

    @cancellable
    def open_channel(self, address: str) -> IOStream:
        """
        Open a device-specific communication channel
        """

        return IOStream(self._impl.open_channel(address))

    @cancellable
    def open_service(self, address: str) -> Service:
        """
        Open a device-specific service
        """

        return Service(self._impl.open_service(address))

    @cancellable
    def unpair(self) -> None:
        """
        Unpair device
        """

        self._impl.unpair()

    @cancellable
    def get_bus(self) -> Bus:
        """
        Get the message bus of the device
        """

        return self.bus

    @overload
    def on(self, signal: Literal["spawn-added"], callback: DeviceSpawnAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["spawn-removed"], callback: DeviceSpawnRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["child-added"], callback: DeviceChildAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["child-removed"], callback: DeviceChildRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["process-crashed"], callback: DeviceProcessCrashedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["output"], callback: DeviceOutputCallback) -> None: ...

    @overload
    def on(self, signal: Literal["uninjected"], callback: DeviceUninjectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["lost"], callback: DeviceLostCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["spawn-added"], callback: DeviceSpawnAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["spawn-removed"], callback: DeviceSpawnRemovedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["child-added"], callback: DeviceChildAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["child-removed"], callback: DeviceChildRemovedCallback) -> None: ...

    @overload
    def of
"""


```