Response:
### 功能归纳

`droidy-host-session.vala` 是 Frida 工具中用于与 Android 设备进行通信的核心模块之一。它主要负责与 Android 设备的 `frida-helper` 进程进行交互，管理设备的连接、会话、以及进程的注入和调试。以下是该文件的主要功能：

1. **设备连接管理**：
   - 负责与 Android 设备建立连接，管理设备的生命周期。
   - 处理设备的连接、断开、重连等事件。

2. **会话管理**：
   - 管理与 Android 设备上的 `frida-helper` 进程的会话。
   - 负责会话的创建、销毁、以及会话状态的维护。

3. **进程注入与调试**：
   - 负责将 Frida 的 JavaScript 代码注入到目标进程中。
   - 提供调试功能，允许用户通过 Frida 的 API 对目标进程进行动态调试。

4. **通信协议处理**：
   - 处理与 Android 设备之间的通信协议，确保数据的正确传输和解析。
   - 处理来自设备的响应，并将其转换为 Frida 的 API 调用。

5. **错误处理与日志记录**：
   - 处理与设备通信过程中可能出现的错误，并提供相应的错误处理机制。
   - 记录调试日志，帮助开发者排查问题。

### 涉及二进制底层与 Linux 内核的举例

1. **进程注入**：
   - 在 Android 设备上，Frida 通过 `ptrace` 系统调用将代码注入到目标进程中。`ptrace` 是 Linux 内核提供的系统调用，用于进程调试和控制。Frida 利用 `ptrace` 来附加到目标进程，并在目标进程中加载 Frida 的共享库（如 `frida-agent.so`）。

2. **动态链接库加载**：
   - Frida 在注入过程中会加载 `frida-agent.so`，这是一个动态链接库，包含了 Frida 的核心功能。加载过程涉及到 Linux 的 `dlopen` 和 `dlsym` 函数，这些函数用于动态加载和解析共享库中的符号。

3. **内存操作**：
   - Frida 在调试过程中会直接操作目标进程的内存，读取和修改内存中的数据。这涉及到 Linux 的 `/proc/<pid>/mem` 文件，该文件提供了对进程内存的直接访问。

### LLDB 调试示例

假设我们想要调试 Frida 的进程注入功能，可以使用 LLDB 来跟踪 `ptrace` 系统调用的执行过程。以下是一个简单的 LLDB Python 脚本示例，用于跟踪 `ptrace` 调用：

```python
import lldb

def ptrace_trace(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    
    # 设置断点在 ptrace 函数
    breakpoint = target.BreakpointCreateByName("ptrace")
    
    # 当断点命中时，打印调用参数
    def ptrace_callback(frame, bp_loc, dict):
        thread = frame.GetThread()
        process = thread.GetProcess()
        ptrace_call = frame.FindVariable("request")
        pid = frame.FindVariable("pid")
        addr = frame.FindVariable("addr")
        data = frame.FindVariable("data")
        
        print(f"ptrace called with request={ptrace_call.GetValue()}, pid={pid.GetValue()}, addr={addr.GetValue()}, data={data.GetValue()}")
        
        # 继续执行
        process.Continue()
    
    breakpoint.SetScriptCallbackFunction("ptrace_callback")
    
    # 继续执行程序
    process.Continue()

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f ptrace_trace.ptrace_trace ptrace_trace')
```

### 假设输入与输出

**输入**：
- 目标进程的 PID。
- 要注入的 JavaScript 代码。

**输出**：
- 注入成功或失败的状态。
- 目标进程的调试信息。

### 常见使用错误举例

1. **权限不足**：
   - 用户尝试注入一个需要 root 权限的进程，但没有以 root 权限运行 Frida。
   - **解决方法**：确保以 root 权限运行 Frida，或者使用 `frida-server` 在设备上以 root 权限运行。

2. **目标进程崩溃**：
   - 注入的 JavaScript 代码导致目标进程崩溃。
   - **解决方法**：检查 JavaScript 代码，确保没有内存泄漏或非法操作。

3. **设备连接失败**：
   - 设备未正确连接或 `frida-server` 未启动。
   - **解决方法**：确保设备通过 USB 连接，并且 `frida-server` 已在设备上运行。

### 用户操作步骤

1. **启动 Frida**：
   - 用户在主机上启动 Frida，并指定目标设备。

2. **连接设备**：
   - Frida 通过 ADB 连接到 Android 设备，并启动 `frida-server`。

3. **选择目标进程**：
   - 用户选择要调试的目标进程，Frida 通过 `ptrace` 附加到该进程。

4. **注入 JavaScript 代码**：
   - Frida 将 JavaScript 代码注入到目标进程中，并开始调试。

5. **调试与监控**：
   - 用户通过 Frida 的 API 监控目标进程的行为，并动态修改其状态。

6. **结束调试**：
   - 用户结束调试会话，Frida 从目标进程中分离，并清理资源。

### 总结

`droidy-host-session.vala` 是 Frida 工具中用于与 Android 设备通信的核心模块，负责设备连接、会话管理、进程注入与调试等功能。它涉及到 Linux 内核的系统调用（如 `ptrace`）和动态链接库的加载（如 `dlopen`）。通过 LLDB 可以跟踪这些系统调用的执行过程，帮助开发者深入理解 Frida 的工作原理。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/droidy/droidy-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
, 0x00, 0x0a, 0x00, 0x38, 0x00, 0x10, 0x00, 0x72, 0x10,
			0x62, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x1f, 0x00, 0x0d, 0x00, 0x54, 0x00, 0x0d, 0x00, 0x54, 0x00, 0x03, 0x00, 0x72,
			0x20, 0x63, 0x00, 0x01, 0x00, 0x28, 0xed, 0x11, 0x01, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00,
			0x56, 0x3e, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x62, 0x00, 0x13, 0x00, 0x1a, 0x01, 0x81, 0x00, 0x6e, 0x20, 0x36,
			0x00, 0x10, 0x00, 0x54, 0x30, 0x22, 0x00, 0x6e, 0x10, 0x14, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x22, 0x01, 0x50, 0x00,
			0x1a, 0x02, 0x13, 0x00, 0x70, 0x40, 0x7f, 0x00, 0x31, 0x02, 0x6e, 0x10, 0x54, 0x00, 0x01, 0x00, 0x28, 0xf0, 0x0d,
			0x00, 0x0e, 0x00, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01, 0x01, 0x27, 0x18, 0x07, 0x00, 0x01, 0x00,
			0x03, 0x00, 0x02, 0x00, 0x61, 0x3e, 0x00, 0x00, 0xa5, 0x00, 0x00, 0x00, 0x12, 0x15, 0x12, 0x01, 0x21, 0x60, 0x32,
			0x50, 0x0d, 0x00, 0x62, 0x00, 0x12, 0x00, 0x1a, 0x01, 0x85, 0x00, 0x6e, 0x20, 0x36, 0x00, 0x10, 0x00, 0x71, 0x10,
			0x52, 0x00, 0x05, 0x00, 0x0e, 0x00, 0x46, 0x00, 0x06, 0x01, 0x22, 0x01, 0x25, 0x00, 0x22, 0x02, 0x37, 0x00, 0x70,
			0x10, 0x4f, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x08, 0x00, 0x6e, 0x20, 0x50, 0x00, 0x32, 0x00, 0x0c, 0x02, 0x6e, 0x20,
			0x50, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x1a, 0x03, 0x07, 0x00, 0x6e, 0x20, 0x50, 0x00, 0x32, 0x00, 0x0c, 0x02, 0x6e,
			0x10, 0x51, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x70, 0x20, 0x2b, 0x00, 0x21, 0x00, 0x6e, 0x10, 0x2d, 0x00, 0x01, 0x00,
			0x22, 0x01, 0x13, 0x00, 0x22, 0x02, 0x37, 0x00, 0x70, 0x10, 0x4f, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x09, 0x00, 0x6e,
			0x20, 0x50, 0x00, 0x32, 0x00, 0x0c, 0x02, 0x6e, 0x20, 0x50, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x6e, 0x10, 0x51, 0x00,
			0x00, 0x00, 0x0c, 0x00, 0x70, 0x20, 0x13, 0x00, 0x01, 0x00, 0x71, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1a, 0x00, 0xa3,
			0x00, 0x71, 0x10, 0x37, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x1a, 0x02, 0x2e, 0x01, 0x12, 0x03, 0x23, 0x33, 0x58, 0x00,
			0x6e, 0x30, 0x39, 0x00, 0x20, 0x03, 0x0c, 0x02, 0x12, 0x03, 0x12, 0x04, 0x23, 0x44, 0x59, 0x00, 0x6e, 0x30, 0x57,
			0x00, 0x32, 0x04, 0x0c, 0x02, 0x1a, 0x03, 0xe8, 0x00, 0x12, 0x04, 0x23, 0x44, 0x58, 0x00, 0x6e, 0x30, 0x39, 0x00,
			0x30, 0x04, 0x0c, 0x00, 0x12, 0x03, 0x23, 0x33, 0x59, 0x00, 0x6e, 0x30, 0x57, 0x00, 0x20, 0x03, 0x0c, 0x00, 0x1f,
			0x00, 0x06, 0x00, 0x22, 0x02, 0x52, 0x00, 0x70, 0x30, 0x85, 0x00, 0x12, 0x00, 0x70, 0x10, 0x99, 0x00, 0x02, 0x00,
			0x28, 0x90, 0x0d, 0x00, 0x62, 0x01, 0x12, 0x00, 0x6e, 0x20, 0x35, 0x00, 0x01, 0x00, 0x12, 0x20, 0x71, 0x10, 0x52,
			0x00, 0x00, 0x00, 0x28, 0x85, 0x0d, 0x00, 0x62, 0x01, 0x12, 0x00, 0x6e, 0x10, 0x56, 0x00, 0x00, 0x00, 0x0c, 0x00,
			0x6e, 0x20, 0x35, 0x00, 0x01, 0x00, 0x71, 0x10, 0x52, 0x00, 0x05, 0x00, 0x29, 0x00, 0x77, 0xff, 0x0d, 0x00, 0x62,
			0x01, 0x12, 0x00, 0x6e, 0x20, 0x35, 0x00, 0x01, 0x00, 0x71, 0x10, 0x52, 0x00, 0x05, 0x00, 0x29, 0x00, 0x6c, 0xff,
			0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x29, 0x00, 0x05, 0x00, 0x02,
			0x01, 0x27, 0x80, 0x01, 0x02, 0x3c, 0x8b, 0x01, 0x2e, 0x9a, 0x01, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
			0x8d, 0x3e, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x22, 0x00, 0x25, 0x00, 0x1a, 0x01, 0x0c, 0x00, 0x70, 0x20, 0x2b,
			0x00, 0x10, 0x00, 0x71, 0x10, 0x90, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x1a, 0x01, 0x99, 0x00, 0x13, 0x02, 0x08, 0x00,
			0x71, 0x20, 0x6e, 0x00, 0x21, 0x00, 0x0c, 0x01, 0x6e, 0x20, 0x6f, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x6e, 0x10, 0x6c,
			0x00, 0x00, 0x00, 0x12, 0x11, 0x6e, 0x20, 0x6d, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x71, 0x10, 0x41, 0x00, 0x00, 0x00,
			0x0b, 0x00, 0x16, 0x02, 0xe8, 0x03, 0xbd, 0x20, 0x10, 0x00, 0x0d, 0x00, 0x22, 0x01, 0x35, 0x00, 0x70, 0x20, 0x44,
			0x00, 0x01, 0x00, 0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x01, 0x01, 0x27, 0x27, 0x08, 0x00,
			0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x9a, 0x3e, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x54, 0x60, 0x21, 0x00, 0x54,
			0x61, 0x1c, 0x00, 0x12, 0x02, 0x12, 0x13, 0x23, 0x33, 0x59, 0x00, 0x12, 0x04, 0x71, 0x10, 0x40, 0x00, 0x07, 0x00,
			0x0c, 0x05, 0x4d, 0x05, 0x03, 0x04, 0x6e, 0x30, 0x57, 0x00, 0x21, 0x03, 0x0c, 0x01, 0x6e, 0x20, 0x55, 0x00, 0x10,
			0x00, 0x0c, 0x00, 0x1f, 0x00, 0x36, 0x00, 0x11, 0x00, 0x0d, 0x00, 0x22, 0x01, 0x35, 0x00, 0x70, 0x20, 0x44, 0x00,
			0x01, 0x00, 0x27, 0x01, 0x0d, 0x00, 0x28, 0xf9, 0x0d, 0x00, 0x28, 0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
			0x00, 0x01, 0x00, 0x01, 0x03, 0x30, 0x21, 0x2f, 0x1a, 0x3c, 0x23, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
			0xa6, 0x3e, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x54, 0x10, 0x25, 0x00, 0x6e, 0x10, 0x54, 0x00, 0x00, 0x00, 0x71,
			0x00, 0x18, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x02, 0x00, 0x04, 0x00, 0xae, 0x3e,
			0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x22, 0x01, 0x22, 0x00, 0x22, 0x00, 0x1f, 0x00, 0x6e, 0x10, 0x16, 0x00, 0x06,
			0x00, 0x0c, 0x02, 0x70, 0x20, 0x1e, 0x00, 0x20, 0x00, 0x70, 0x20, 0x23, 0x00, 0x01, 0x00, 0x22, 0x02, 0x23, 0x00,
			0x22, 0x00, 0x20, 0x00, 0x6e, 0x10, 0x17, 0x00, 0x06, 0x00, 0x0c, 0x03, 0x70, 0x20, 0x1f, 0x00, 0x30, 0x00, 0x70,
			0x20, 0x26, 0x00, 0x02, 0x00, 0x6e, 0x10, 0x25, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x12, 0x13, 0x34, 0x30, 0x06, 0x00,
			0x15, 0x03, 0x02, 0x00, 0x37, 0x30, 0x06, 0x00, 0x6e, 0x10, 0x15, 0x00, 0x06, 0x00, 0x0e, 0x00, 0x23, 0x00, 0x56,
			0x00, 0x6e, 0x20, 0x24, 0x00, 0x01, 0x00, 0x22, 0x03, 0x4c, 0x00, 0x22, 0x04, 0x36, 0x00, 0x70, 0x20, 0x45, 0x00,
			0x04, 0x00, 0x70, 0x20, 0x71, 0x00, 0x43, 0x00, 0x12, 0x00, 0x6e, 0x20, 0x74, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x1a,
			0x04, 0xce, 0x00, 0x6e, 0x20, 0x46, 0x00, 0x40, 0x00, 0x0a, 0x04, 0x38, 0x04, 0x1d, 0x00, 0x70, 0x20, 0x91, 0x00,
			0x35, 0x00, 0x0c, 0x00, 0x38, 0x00, 0x31, 0x00, 0x6e, 0x10, 0x78, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x6e, 0x10, 0x47,
			0x00, 0x00, 0x00, 0x0c, 0x00, 0x21, 0x03, 0x6e, 0x20, 0x29, 0x00, 0x32, 0x00, 0x6e, 0x20, 0x28, 0x00, 0x02, 0x00,
			0x6e, 0x10, 0x27, 0x00, 0x02, 0x00, 0x28, 0xbd, 0x0d, 0x00, 0x28, 0xc6, 0x1a, 0x04, 0xbc, 0x00, 0x6e, 0x20, 0x46,
			0x00, 0x40, 0x00, 0x0a, 0x04, 0x38, 0x04, 0x07, 0x00, 0x70, 0x20, 0x8a, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x28, 0xdd,
			0x1a, 0x04, 0xbd, 0x00, 0x6e, 0x20, 0x46, 0x00, 0x40, 0x00, 0x0a, 0x00, 0x38, 0x00, 0xb2, 0xff, 0x70, 0x20, 0x8b,
			0x00, 0x35, 0x00, 0x0c, 0x00, 0x28, 0xd0, 0x62, 0x00, 0x15, 0x00, 0x6e, 0x10, 0x43, 0x00, 0x00, 0x00, 0x0c, 0x00,
			0x6e, 0x10, 0x47, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x28, 0xcf, 0x0d, 0x00, 0x28, 0xa2, 0x0d, 0x00, 0x28, 0x9d, 0x0d,
			0x00, 0x28, 0x9b, 0x0d, 0x00, 0x28, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x0e, 0x00, 0x1c, 0x00,
			0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x27, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x5a,
			0x00, 0x01, 0x00, 0x03, 0x03, 0x4d, 0x60, 0x24, 0x8b, 0x01, 0x27, 0x89, 0x01, 0x01, 0x27, 0x87, 0x01, 0x01, 0x27,
			0x8d, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdb, 0x3e, 0x00, 0x00, 0x13, 0x00, 0x00,
			0x00, 0x12, 0x30, 0x23, 0x00, 0x5b, 0x00, 0x12, 0x01, 0x62, 0x02, 0x2a, 0x00, 0x4d, 0x02, 0x00, 0x01, 0x12, 0x11,
			0x62, 0x02, 0x29, 0x00, 0x4d, 0x02, 0x00, 0x01, 0x12, 0x21, 0x62, 0x02, 0x28, 0x00, 0x4d, 0x02, 0x00, 0x01, 0x11,
			0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xe1, 0x3e, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
			0x22, 0x00, 0x53, 0x00, 0x1a, 0x01, 0x7e, 0x00, 0x12, 0x02, 0x70, 0x30, 0x9c, 0x00, 0x10, 0x02, 0x69, 0x00, 0x2a,
			0x00, 0x22, 0x00, 0x53, 0x00, 0x1a, 0x01, 0x7d, 0x00, 0x12, 0x12, 0x70, 0x30, 0x9c, 0x00, 0x10, 0x02, 0x69, 0x00,
			0x29, 0x00, 0x22, 0x00, 0x53, 0x00, 0x1a, 0x01, 0x15, 0x00, 0x12, 0x22, 0x70, 0x30, 0x9c, 0x00, 0x10, 0x02, 0x69,
			0x00, 0x28, 0x00, 0x71, 0x00, 0x9a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x69, 0x00, 0x27, 0x00, 0x0e, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0xea, 0x3e, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x70, 0x30, 0x3a,
			0x00, 0x10, 0x02, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xf2, 0x3e, 0x00, 0x00, 0x09, 0x00,
			0x00, 0x00, 0x1c, 0x00, 0x53, 0x00, 0x71, 0x20, 0x3b, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x1f, 0x00, 0x53, 0x00, 0x11,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf9, 0x3e, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
			0x62, 0x00, 0x27, 0x00, 0x6e, 0x10, 0x9f, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x1f, 0x00, 0x5b, 0x00, 0x11, 0x00, 0x00,
			0x00, 0x28, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x12, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00, 0x70, 0x12, 0x00, 0x00, 0x8a, 0x00, 0x00,
			0x00, 0x50, 0x12, 0x00, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x50, 0x12, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x60, 0x12,
			0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x68, 0x12, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x70, 0x12, 0x00, 0x00, 0x91,
			0x00, 0x00, 0x00, 0x50, 0x12, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x58, 0x12, 0x00, 0x00, 0x78, 0x12, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00, 0x80, 0x12, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
			0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x36, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x59, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x58, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x2b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00,
			0x53, 0x00, 0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x55, 0x00, 0x04,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
			0x00, 0x13, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x25, 0x00,
			0x36, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x36, 0x00, 0x36, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x36, 0x00, 0x47, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x46, 0x00, 0x42,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x52, 0x00, 0x36, 0x00, 0x03, 0x00, 0x00, 0x00, 0x52,
			0x00, 0x36, 0x00, 0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x29, 0x00, 0x01,
			0x20, 0x00, 0x02, 0x20, 0x2d, 0x00, 0x07, 0x24, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x53, 0x00, 0x06, 0x24, 0x69, 0x63,
			0x6f, 0x6e, 0x73, 0x00, 0x07, 0x24, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x00, 0x02, 0x28, 0x29, 0x00, 0x03, 0x28,
			0x29, 0x56, 0x00, 0x04, 0x2e, 0x64, 0x65, 0x78, 0x00, 0x1d, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x6c, 0x6f, 0x63,
			0x61, 0x6c, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2d, 0x68, 0x65, 0x6c, 0x70, 0x65, 0x72,
			0x2d, 0x00, 0x0e, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2d, 0x68, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x2d, 0x00, 0x05,
			0x2f, 0x70, 0x72, 0x6f, 0x63, 0x00, 0x06, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x00, 0x0a, 0x2f, 0x70, 0x72, 0x6f,
			0x63, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x00, 0x01, 0x3c, 0x00, 0x08, 0x3c, 0x63, 0x6c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
			0x00, 0x06, 0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, 0x00, 0x02, 0x3e, 0x3b, 0x00, 0x04, 0x3e, 0x3b, 0x3e, 0x3b, 0x00,
			0x09, 0x41, 0x52, 0x47, 0x42, 0x5f, 0x38, 0x38, 0x38, 0x38, 0x00, 0x12, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
			0x69, 0x6f, 0x6e, 0x20, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x00, 0x13, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
			0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x00, 0x04, 0x46, 0x55, 0x4c, 0x4c,
			0x00, 0x0b, 0x48, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x2e, 0x6a, 0x61, 0x76, 0x61, 0x00, 0x01, 0x49, 0x00, 0x02, 0x49,
			0x49, 0x00, 0x02, 0x49, 0x4c, 0x00, 0x03, 0x49, 0x4c, 0x4c, 0x00, 0x01, 0x4a, 0x00, 0x02, 0x4a, 0x49, 0x00, 0x02,
			0x4a, 0x4c, 0x00, 0x01, 0x4c, 0x00, 0x02, 0x4c, 0x49, 0x00, 0x03, 0x4c, 0x49, 0x49, 0x00, 0x04, 0x4c, 0x49, 0x49,
			0x4c, 0x00, 0x02, 0x4c, 0x4c, 0x00, 0x03, 0x4c, 0x4c, 0x49, 0x00, 0x03, 0x4c, 0x4c, 0x4c, 0x00, 0x03, 0x4c, 0x4c,
			0x5a, 0x00, 0x33, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x41, 0x63, 0x74,
			0x69, 0x76, 0x69, 0x74, 0x79, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x24, 0x52, 0x75, 0x6e, 0x6e, 0x69, 0x6e,
			0x67, 0x41, 0x70, 0x70, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x3b, 0x00, 0x2d, 0x4c,
			0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
			0x79, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x24, 0x52, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x54, 0x61, 0x73,
			0x6b, 0x49, 0x6e, 0x66, 0x6f, 0x3b, 0x00, 0x1d, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x61, 0x70,
			0x70, 0x2f, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x3b, 0x00,
			0x1f, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x43,
			0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x3b, 0x00, 0x19, 0x4c, 0x61, 0x6e, 0x64,
			0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78,
			0x74, 0x3b, 0x00, 0x18, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
			0x74, 0x2f, 0x49, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x3b, 0x00, 0x21, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64,
			0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
			0x79, 0x49, 0x6e, 0x66, 0x6f, 0x3b, 0x00, 0x24, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f,
			0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
			0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x3b, 0x00, 0x20, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f,
			0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66,
			0x6f, 0x3b, 0x00, 0x39, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
			0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
			0x24, 0x4e, 0x61, 0x6d, 0x65, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74,
			0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x23, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
			0x65, 0x6e, 0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x6e, 0x61, 0x67,
			0x65, 0x72, 0x3b, 0x00, 0x20, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65,
			0x6e, 0x74, 0x2f, 0x70, 0x6d, 0x2f, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3b, 0x00,
			0x28, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73, 0x2f,
			0x42, 0x69, 0x74, 0x6d, 0x61, 0x70, 0x24, 0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x46, 0x6f, 0x72, 0x6d,
			0x61, 0x74, 0x3b, 0x00, 0x20, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68,
			0x69, 0x63, 0x73, 0x2f, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x70, 0x24, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3b, 0x00,
			0x19, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73, 0x2f,
			0x42, 0x69, 0x74, 0x6d, 0x61, 0x70, 0x3b, 0x00, 0x19, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x67,
			0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73, 0x2f, 0x43, 0x61, 0x6e, 0x76, 0x61, 0x73, 0x3b, 0x00, 0x24, 0x4c, 0x61,
			0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73, 0x2f, 0x64, 0x72, 0x61,
			0x77, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x44, 0x72, 0x61, 0x77, 0x61, 0x62, 0x6c, 0x65, 0x3b, 0x00, 0x1f, 0x4c, 0x61,
			0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x53, 0x65, 0x72,
			0x76, 0x65, 0x72, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x3b, 0x00, 0x19, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69,
			0x64, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x3b, 0x00,
			0x13, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x6f, 0x73, 0x2f, 0x4c, 0x6f, 0x6f, 0x70, 0x65, 0x72,
			0x3b, 0x00, 0x14, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x6f, 0x73, 0x2f, 0x50, 0x72, 0x6f, 0x63,
			0x65, 0x73, 0x73, 0x3b, 0x00, 0x1f, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x73, 0x79, 0x73, 0x74,
			0x65, 0x6d, 0x2f, 0x45, 0x72, 0x72, 0x6e, 0x6f, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00,
			0x13, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x4f, 0x73,
			0x3b, 0x00, 0x1c, 0x4c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f,
			0x4f, 0x73, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x73, 0x3b, 0x00, 0x21, 0x4c, 0x61, 0x6e, 0x64, 0x72,
			0x6f, 0x69, 0x64, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x42, 0x61, 0x73, 0x65, 0x36, 0x34, 0x4f, 0x75, 0x74, 0x70,
			0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x23, 0x4c, 0x64, 0x61, 0x6c, 0x76, 0x69, 0x6b, 0x2f,
			0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x45, 0x6e, 0x63, 0x6c, 0x6f, 0x73, 0x69, 0x6e,
			0x67, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x3b, 0x00, 0x1e, 0x4c, 0x64, 0x61, 0x6c, 0x76, 0x69, 0x6b, 0x2f, 0x61,
			0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x49, 0x6e, 0x6e, 0x65, 0x72, 0x43, 0x6c, 0x61, 0x73,
			0x73, 0x3b, 0x00, 0x1d, 0x4c, 0x64, 0x61, 0x6c, 0x76, 0x69, 0x6b, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
			0x69, 0x6f, 0x6e, 0x2f, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x3b, 0x00, 0x1a, 0x4c, 0x64, 0x61,
			0x6c, 0x76, 0x69, 0x6b, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x54, 0x68, 0x72,
			0x6f, 0x77, 0x73, 0x3b, 0x00, 0x1d, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x42, 0x75, 0x66, 0x66,
			0x65, 0x72, 0x65, 0x64, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x1e, 0x4c,
			0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x65, 0x64, 0x4f, 0x75, 0x74,
			0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x1f, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69,
			0x6f, 0x2f, 0x42, 0x79, 0x74, 0x65, 0x41, 0x72, 0x72, 0x61, 0x79, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x53, 0x74,
			0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x19, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x44, 0x61, 0x74,
			0x61, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x1a, 0x4c, 0x6a, 0x61, 0x76,
			0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x44, 0x61, 0x74, 0x61, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65,
			0x61, 0x6d, 0x3b, 0x00, 0x16, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x45, 0x4f, 0x46, 0x45, 0x78,
			0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x0e, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f,
			0x46, 0x69, 0x6c, 0x65, 0x3b, 0x00, 0x19, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x46, 0x69, 0x6c,
			0x65, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x15, 0x4c, 0x6a, 0x61, 0x76,
			0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x49, 0x4f, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x15,
			0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61,
			0x6d, 0x3b, 0x00, 0x16, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74,
			0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x15, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x50,
			0x72, 0x69, 0x6e, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3b, 0x00, 0x18, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f,
			0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x43, 0x68, 0x61, 0x72, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x3b, 0x00,
			0x11, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3b, 0x00,
			0x0f, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x45, 0x6e, 0x75, 0x6d, 0x00, 0x10, 0x4c,
			0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x45, 0x6e, 0x75, 0x6d, 0x3b, 0x00, 0x15, 0x4c, 0x6a,
			0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b,
			0x00, 0x22, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x49, 0x6c, 0x6c, 0x65, 0x67, 0x61,
			0x6c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x24,
			0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x49, 0x6c, 0x6c, 0x65, 0x67, 0x61, 0x6c, 0x41,
			0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x13,
			0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x3b,
			0x00, 0x10, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4c, 0x6f, 0x6e, 0x67, 0x3b, 0x00,
			0x21, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x46,
			0x6f, 0x72, 0x6d, 0x61, 0x74, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x12, 0x4c, 0x6a,
			0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x00, 0x1c, 0x4c,
			0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x45, 0x78,
			0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
			0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x00, 0x19, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
			0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x3b, 0x00, 0x12,
			0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3b, 0x00,
			0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x3b,
			0x00, 0x15, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x54, 0x68, 0x72, 0x6f, 0x77, 0x61,
			0x62, 0x6c, 0x65, 0x3b, 0x00, 0x19, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x72, 0x65,
			0x66, 0x6c, 0x65, 0x63, 0x74, 0x2f, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x3b, 0x00, 0x2d, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x72, 0x65, 0x66, 0x6c, 0x65, 0x63, 0x74, 0x2f, 0x49, 0x6e, 0x76, 0x6f, 0x63,
			0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f,
			0x6e, 0x3b, 0x00, 0x1a, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x72, 0x65, 0x66, 0x6c,
			0x65, 0x63, 0x74, 0x2f, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x3b, 0x00, 0x1c, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f,
			0x74, 0x65, 0x78, 0x74, 0x2f, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x44, 0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x6d,
			0x61, 0x74, 0x3b, 0x00, 0x15, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x41, 0x72, 0x72,
			0x61, 0x79, 0x4c, 0x69, 0x73, 0x74, 0x3b, 0x00, 0x16, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c,
			0x2f, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x17, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3b, 0x00,
			0x15, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x72, 0x61,
			0x74, 0x6f, 0x72, 0x00, 0x16, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x43, 0x6f, 0x6d,
			0x70, 0x61, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x3b, 0x00, 0x10, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69,
			0x6c, 0x2f, 0x44, 0x61, 0x74, 0x65, 0x3b, 0x00, 0x13, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c,
			0x2f, 0x48, 0x61, 0x73, 0x68, 0x4d, 0x61, 0x70, 0x3b, 0x00, 0x14, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74,
			0x69, 0x6c, 0x2f, 0x49, 0x74, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x3b, 0x00, 0x0f, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x4c, 0x69, 0x73, 0x74, 0x00, 0x10, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75,
			0x74, 0x69, 0x6c, 0x2f, 0x4c, 0x69, 0x73, 0x74, 0x3b, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74,
			0x69, 0x6c, 0x2f, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65, 0x3b, 0x00, 0x0e, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75,
			0x74, 0x69, 0x6c, 0x2f, 0x4d, 0x61, 0x70, 0x00, 0x0f, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c,
			0x2f, 0x4d, 0x61, 0x70, 0x3b, 0x00, 0x14, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x54,
			0x69, 0x6d, 0x65, 0x5a, 0x6f, 0x6e, 0x65, 0x3b, 0x00, 0x19, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69,
			0x6c, 0x2f, 0x72, 0x65, 0x67, 0x65, 0x78, 0x2f, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x3b, 0x00, 0x19, 0x4c,
			0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x72, 0x65, 0x67, 0x65, 0x78, 0x2f, 0x50, 0x61, 0x74,
			0x74, 0x65, 0x72, 0x6e, 0x3b, 0x00, 0x14, 0x4c, 0x6f, 0x72, 0x67, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x2f, 0x4a, 0x53,
			0x4f, 0x4e, 0x41, 0x72, 0x72, 0x61, 0x79, 0x3b, 0x00, 0x18, 0x4c, 0x6f, 0x72, 0x67, 0x2f, 0x6a, 0x73, 0x6f, 0x6e,
			0x2f, 0x4a, 0x53, 0x4f, 0x4e, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x15, 0x4c, 0x6f,
			0x72, 0x67, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x2f, 0x4a, 0x53, 0x4f, 0x4e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b,
			0x00, 0x13, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x48, 0x65, 0x6c, 0x70, 0x65, 0x72, 0x24,
			0x31, 0x3b, 0x00, 0x13, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x48, 0x65, 0x6c, 0x70, 0x65,
			0x72, 0x24, 0x32, 0x3b, 0x00, 0x13, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x48, 0x65, 0x6c,
			0x70, 0x65, 0x72, 0x24, 0x33, 0x3b, 0x00, 0x11, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x48,
			0x65, 0x6c, 0x70, 0x65, 0x72, 0x3b, 0x00, 0x10, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x53,
			0x63, 0x6f, 0x70, 0x65, 0x3b, 0x00, 0x10, 0x4d, 0x41, 0x58, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x5f,
			0x53, 0x49, 0x5a, 0x45, 0x00, 0x08, 0x4d, 0x45, 0x54, 0x41, 0x44, 0x41, 0x54, 0x41, 0x00, 0x07, 0x4d, 0x49, 0x4e,
			0x49, 0x4d, 0x41, 0x4c, 0x00, 0x04, 0x4e, 0x55, 0x4c, 0x4c, 0x00, 0x03, 0x50, 0x4e, 0x47, 0x00, 0x06, 0x52, 0x45,
			0x41, 0x44, 0x59, 0x2e, 0x00, 0x04, 0x54, 0x59, 0x50, 0x45, 0x00, 0x02, 0x55, 0x53, 0x00, 0x03, 0x55, 0x54, 0x43,
			0x00, 0x21, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2d, 0x68, 0x65, 0x6c, 0x70,
			0x65, 0x72, 0x20, 0x3c, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x69, 0x64, 0x3e, 0x00, 0x01, 0x56,
			0x00, 0x02, 0x56, 0x49, 0x00, 0x05, 0x56, 0x49, 0x49, 0x49, 0x49, 0x00, 0x02, 0x56, 0x4a, 0x00, 0x02, 0x56, 0x4c,
			0x00, 0x03, 0x56, 0x4c, 0x49, 0x00, 0x04, 0x56, 0x4c, 0x49, 0x49, 0x00, 0x03, 0x56, 0x4c, 0x4c, 0x00, 0x04, 0x56,
			0x4c, 0x4c, 0x4c, 0x00, 0x01, 0x5a, 0x00, 0x02, 0x5a, 0x4c, 0x00, 0x04, 0x5a, 0x4c, 0x49, 0x4c, 0x00, 0x02, 0x5b,
			0x42, 0x00, 0x0f, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x46, 0x69, 0x6c, 0x65, 0x3b, 0x00,
			0x12, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3b,
			0x00, 0x13, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63,
			0x74, 0x3b, 0x00, 0x13, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72,
			0x69, 0x6e, 0x67, 0x3b, 0x00, 0x11, 0x5b, 0x4c, 0x72, 0x65, 0x2f, 0x66, 0x72, 0x69, 0x64, 0x61, 0x2f, 0x53, 0x63,
			0x6f, 0x70, 0x65, 0x3b, 0x00, 0x20, 0x5e, 0x55, 0x69, 0x64, 0x3a, 0x5c, 0x73, 0x2b, 0x5c, 0x64, 0x2b, 0x5c, 0x73,
			0x2b, 0x28, 0x5c, 0x64, 0x2b, 0x29, 0x5c, 0x73, 0x2b, 0x5c, 0x64, 0x2b, 0x5c, 0x73, 0x2b, 0x5c, 0x64, 0x2b, 0x24,
			0x00, 0x0d, 0x5e, 0x62, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x28, 0x5c, 0x64, 0x2b, 0x29, 0x24, 0x00, 0x0b, 0x5f, 0x53,
			0x43, 0x5f, 0x43, 0x4c, 0x4b, 0x5f, 0x54, 0x43, 0x4b, 0x00, 0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00, 0x0a,
			0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x24, 0x30, 0x30, 0x30, 0x00, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x46,
			0x6c, 0x61, 0x67, 0x73, 0x00, 0x08, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x00, 0x0c, 0x61, 0x63, 0x74,
			0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x00, 0x03, 0x61, 0x64, 0x64, 0x00, 0x0b, 0x61, 0x64, 0x64,
			0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x00, 0x12, 0x61, 0x64, 0x64, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73,
			0x73, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x00, 0x1a, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e,
			0x61, 0x70, 0x70, 0x2e, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x00,
			0x14, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x54, 0x61, 0x73, 0x6b, 0x49, 0x6e,
			0x66, 0x6f, 0x00, 0x1a, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e,
			0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x4d, 0x41, 0x49, 0x4e, 0x00, 0x1c, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69,
			0x64, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x2e, 0x48,
			0x4f, 0x4d, 0x45, 0x00, 0x20, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74,
			0x2e, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x2e, 0x4c, 0x41, 0x55, 0x4e, 0x43, 0x48, 0x45, 0x52, 0x00,
			0x11, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x4f, 0x73, 0x00,
			0x1b, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x53, 0x74, 0x72,
			0x75, 0x63, 0x74, 0x50, 0x61, 0x73, 0x73, 0x77, 0x64, 0x00, 0x06, 0x61, 0x70, 0x70, 0x65, 0x6e, 0x64, 0x00, 0x0f,
			0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x00, 0x0c, 0x61, 0x70,
			0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x00, 0x05, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x00, 0x05,
			0x63, 0x6c, 0x6f, 0x6e, 0x65, 0x00, 0x05, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x00, 0x07, 0x63, 0x6d, 0x64, 0x6c, 0x69,
			0x6e, 0x65, 0x00, 0x07, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x72, 0x65, 0x00, 0x07, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c,
			0x65, 0x00, 0x08, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x00, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
			0x42, 0x69, 0x74, 0x6d, 0x61, 0x70, 0x00, 0x08, 0x64, 0x61, 0x74, 0x61, 0x2d, 0x64, 0x69, 0x72, 0x00, 0x07, 0x64,
			0x61, 0x74, 0x61, 0x44, 0x69, 0x72, 0x00, 0x0a, 0x64, 0x65, 0x62, 0x75, 0x67, 0x67, 0x61, 0x62, 0x6c, 0x65, 0x00,
			0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x00, 0x1c, 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x50, 0x72, 0x6f, 0x63,
			0x65, 0x73, 0x73, 0x4e, 0x61, 0x6d, 0x65, 0x46, 0x72, 0x6f, 0x6d, 0x43, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65, 0x00,
			0x19, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x4c, 0x61, 0x75, 0x6e,
```