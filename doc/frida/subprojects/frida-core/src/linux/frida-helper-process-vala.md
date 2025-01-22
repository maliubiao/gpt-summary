Response:
### 功能概述

`frida-helper-process.vala` 是 Frida 动态插桩工具的核心组件之一，主要负责在 Linux 系统上管理和执行与进程注入、调试相关的操作。以下是该文件的主要功能：

1. **进程管理**：
   - `spawn`：启动一个新的进程。
   - `kill`：终止指定的进程。
   - `resume`：恢复指定进程的执行。
   - `prepare_exec_transition`、`await_exec_transition`、`cancel_exec_transition`：处理进程执行状态转换（如 `exec` 系统调用）的相关操作。

2. **进程注入**：
   - `inject_library`：将指定的共享库（`.so` 文件）注入到目标进程中。
   - `demonitor`、`demonitor_and_clone_injectee_state`、`recreate_injectee_thread`：管理与注入相关的监控、状态克隆和线程重建。

3. **系统调用管理**：
   - `await_syscall`：等待目标进程执行指定的系统调用。
   - `resume_syscall`：恢复目标进程的系统调用执行。

4. **进程间通信**：
   - `input`：向目标进程发送输入数据。
   - `request_control_channel`：请求与目标进程的控制通道，用于进一步的通信和控制。

5. **资源管理**：
   - `ResourceStore`：管理临时文件和资源，如 32 位和 64 位的帮助程序（`helper32` 和 `helper64`）。

6. **错误处理**：
   - 通过 `throw_dbus_error` 和 `throw_api_error` 处理 DBus 和 API 调用中的错误。

### 二进制底层与 Linux 内核相关

1. **进程注入**：
   - `inject_library` 方法通过 `ptrace` 系统调用或其他底层机制将共享库注入到目标进程中。这涉及到修改目标进程的内存空间、加载共享库、执行库中的入口函数等操作。

2. **系统调用管理**：
   - `await_syscall` 和 `resume_syscall` 方法依赖于 `ptrace` 系统调用，用于监控和控制目标进程的系统调用执行。`ptrace` 是 Linux 内核提供的用于进程调试和控制的系统调用。

3. **进程管理**：
   - `spawn` 和 `kill` 方法分别使用 `fork`、`execve` 和 `kill` 系统调用来创建和终止进程。

### LLDB 调试示例

假设你想调试 `inject_library` 方法的执行过程，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```bash
# 启动 LLDB 并附加到目标进程
lldb -- <target_process>

# 设置断点
b frida-helper-process.vala:inject_library

# 运行进程
run

# 当断点触发时，查看变量和调用栈
frame variable
bt
```

#### LLDB Python 脚本

```python
import lldb

def inject_library_breakpoint(frame, bp_loc, dict):
    print("Breakpoint hit in inject_library method")
    print("Arguments:")
    print(frame.FindVariable("pid"))
    print(frame.FindVariable("library_so"))
    print(frame.FindVariable("entrypoint"))
    print(frame.FindVariable("data"))
    print(frame.FindVariable("features"))
    print(frame.FindVariable("id"))
    return False

# 创建调试器实例
debugger = lldb.SBDebugger.Create()

# 创建目标进程
target = debugger.CreateTarget("<target_process>")

# 设置断点
breakpoint = target.BreakpointCreateByName("inject_library", "Frida::LinuxHelperProcess")
breakpoint.SetScriptCallbackFunction("inject_library_breakpoint")

# 启动进程
process = target.LaunchSimple(None, None, os.getcwd())

# 继续执行
process.Continue()
```

### 逻辑推理与输入输出示例

假设 `inject_library` 方法的输入如下：

- `pid`：1234
- `library_so`：`/path/to/library.so`
- `entrypoint`：`agent_main`
- `data`：`"some_data"`
- `features`：`AgentFeatures.NONE`
- `id`：1

**假设输出**：
- 成功注入共享库，并返回控制通道的 `IOStream` 对象。
- 如果注入失败，抛出 `Error` 异常。

### 用户常见错误

1. **权限不足**：
   - 用户尝试注入一个需要 root 权限的进程，但没有以 root 身份运行 Frida。解决方法是以 root 身份运行 Frida。

2. **目标进程不存在**：
   - 用户指定的 `pid` 不存在或已经终止。解决方法是在注入前确保目标进程正在运行。

3. **共享库路径错误**：
   - 用户提供的 `library_so` 路径不存在或无法访问。解决方法是检查路径是否正确，并确保文件权限允许访问。

### 用户操作路径

1. **启动 Frida**：
   - 用户通过命令行或脚本启动 Frida，并指定目标进程。

2. **调用 `inject_library`**：
   - 用户通过 Frida 的 API 调用 `inject_library` 方法，传入目标进程的 `pid`、共享库路径、入口函数等参数。

3. **调试与监控**：
   - 用户通过 Frida 提供的控制通道与注入的共享库进行交互，监控目标进程的行为。

4. **错误处理**：
   - 如果注入过程中出现错误，Frida 会抛出异常，用户需要根据异常信息进行调试和修复。

通过以上步骤，用户可以逐步实现进程注入和调试功能，并在遇到问题时通过调试工具进行排查和修复。
Prompt: 
```
这是目录为frida/subprojects/frida-core/src/linux/frida-helper-process.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
namespace Frida {
	public class LinuxHelperProcess : Object, LinuxHelper {
		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private ResourceStore? _resource_store;

		private MainContext main_context;
		private HelperFactory? factory32;
		private HelperFactory? factory64;
		private Gee.Map<uint, LinuxHelper> injectee_ids = new Gee.HashMap<uint, LinuxHelper> ();

		public LinuxHelperProcess (TemporaryDirectory tempdir) {
			Object (tempdir: tempdir);
		}

		construct {
			main_context = MainContext.ref_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			injectee_ids.clear ();

			if (factory32 != null) {
				yield factory32.close (cancellable);
				factory32 = null;
			}

			if (factory64 != null) {
				yield factory64.close (cancellable);
				factory64 = null;
			}

			_resource_store = null;
		}

		private ResourceStore get_resource_store () throws Error {
			if (_resource_store == null)
				_resource_store = new ResourceStore (tempdir);
			return _resource_store;
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_path (path, cancellable);
			return yield helper.spawn (path, options, cancellable);
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.prepare_exec_transition (pid, cancellable);
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.await_exec_transition (pid, cancellable);
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.cancel_exec_transition (pid, cancellable);
		}

		public async void await_syscall (uint pid, LinuxSyscall mask, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.await_syscall (pid, mask, cancellable);
		}

		public async void resume_syscall (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.resume_syscall (pid, cancellable);
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.input (pid, data, cancellable);
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var cpu_type = cpu_type_from_pid (pid);
			var helper = yield obtain_for_cpu_type (cpu_type, cancellable);
			try {
				yield helper.resume (pid, cancellable);
			} catch (Error e) {
				if (!(e is Error.INVALID_ARGUMENT))
					throw e;
				try {
					if (cpu_type == Gum.CpuType.AMD64 || cpu_type == Gum.CpuType.ARM64)
						helper = yield obtain_for_32bit (cancellable);
					else
						helper = yield obtain_for_64bit (cancellable);
					yield helper.resume (pid, cancellable);
				} catch (Error _e) {
					// Intentionally rethrowing the original error instead of the new error
					throw e;
				}
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			try {
				yield helper.kill (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void inject_library (uint pid, UnixInputStream library_so, string entrypoint, string data,
				AgentFeatures features, uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_cpu_type (cpu_type_from_pid (pid), cancellable);
			try {
				yield helper.inject_library (pid, library_so, entrypoint, data, features, id, cancellable);
				injectee_ids[id] = helper;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async IOStream request_control_channel (uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				return yield helper.request_control_channel (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				yield helper.demonitor (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, AgentFeatures features,
				Cancellable? cancellable) throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				yield helper.demonitor_and_clone_injectee_state (id, clone_id, features, cancellable);
				injectee_ids[clone_id] = helper;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				yield helper.recreate_injectee_thread (pid, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private LinuxHelper obtain_for_injectee_id (uint id) throws Error, IOError {
			var helper = injectee_ids[id];
			if (helper == null)
				throw new Error.INVALID_ARGUMENT ("Invalid injectee ID");
			return helper;
		}

		private async LinuxHelper obtain_for_path (string path, Cancellable? cancellable) throws Error, IOError {
			return yield obtain_for_cpu_type (cpu_type_from_file (path), cancellable);
		}

		private async LinuxHelper obtain_for_pid (uint pid, Cancellable? cancellable) throws Error, IOError {
			return yield obtain_for_cpu_type (cpu_type_from_pid (pid), cancellable);
		}

		private async LinuxHelper obtain_for_cpu_type (Gum.CpuType cpu_type, Cancellable? cancellable) throws Error, IOError {
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
				case Gum.CpuType.MIPS:
					return yield obtain_for_32bit (cancellable);

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					return yield obtain_for_64bit (cancellable);

				default:
					assert_not_reached ();
			}
		}

		private async LinuxHelper obtain_for_32bit (Cancellable? cancellable) throws Error, IOError {
			if (factory32 == null) {
				var store = get_resource_store ();
				if (sizeof (void *) != 4 && store.helper32 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 32-bit processes due to build configuration");
				factory32 = new HelperFactory (store.helper32, store, main_context);
				factory32.lost.connect (on_factory_lost);
				factory32.output.connect (on_factory_output);
				factory32.uninjected.connect (on_factory_uninjected);
			}

			return yield factory32.obtain (cancellable);
		}

		private async LinuxHelper obtain_for_64bit (Cancellable? cancellable) throws Error, IOError {
			if (factory64 == null) {
				var store = get_resource_store ();
				if (sizeof (void *) != 8 && store.helper64 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 64-bit processes due to build configuration");
				factory64 = new HelperFactory (store.helper64, store, main_context);
				factory64.lost.connect (on_factory_lost);
				factory64.output.connect (on_factory_output);
				factory64.uninjected.connect (on_factory_uninjected);
			}

			return yield factory64.obtain (cancellable);
		}

		private void on_factory_lost (LinuxHelper helper) {
			var dead_ids = new Gee.ArrayList<uint> ();
			foreach (var e in injectee_ids.entries) {
				if (e.value == helper)
					dead_ids.add (e.key);
			}

			foreach (var id in dead_ids) {
				injectee_ids.unset (id);

				uninjected (id);
			}
		}

		private void on_factory_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_factory_uninjected (uint id) {
			injectee_ids.unset (id);

			uninjected (id);
		}
	}

	private class HelperFactory {
		public signal void lost (LinuxHelper helper);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		private HelperFile? helper_file;
		private ResourceStore? resource_store;
		private MainContext main_context;
		private SuperSU.Process superprocess;
		private Pid process_pid;
		private DBusConnection connection;
		private LinuxHelper helper;
		private Promise<LinuxHelper> obtain_request;

		public HelperFactory (HelperFile? helper_file, ResourceStore resource_store, MainContext main_context) {
			this.helper_file = helper_file;
			this.resource_store = resource_store;
			this.main_context = main_context;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (helper != null) {
				yield helper.close (cancellable);

				discard_helper ();
			}

			if (connection != null) {
				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}
			}

			if (superprocess != null) {
				yield superprocess.detach (cancellable);
				superprocess = null;
			}
			process_pid = 0;

			resource_store = null;
		}

		public async LinuxHelper obtain (Cancellable? cancellable) throws Error, IOError {
			while (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			obtain_request = new Promise<LinuxHelper> ();

			if (helper_file == null) {
				assign_helper (new LinuxHelperBackend ());

				obtain_request.resolve (helper);
				return helper;
			}

			SuperSU.Process? pending_superprocess = null;
			Pid pending_pid = 0;
			IOStream? pending_stream = null;
			DBusConnection pending_connection = null;
			LinuxRemoteHelper? pending_proxy = null;
			GLib.Error? pending_error = null;

			SocketService? service = null;
			TimeoutSource? timeout_source = null;

			try {
				string socket_path = "/frida-" + Uuid.string_random ();
				string socket_address = "unix:abstract=" + socket_path;

				service = new SocketService ();
				SocketAddress effective_address;
				service.add_address (new UnixSocketAddress.with_type (socket_path, -1, ABSTRACT),
					SocketType.STREAM, SocketProtocol.DEFAULT, null, out effective_address);
				service.start ();

				var idle_source = new IdleSource ();
				idle_source.set_callback (() => {
					obtain.callback ();
					return false;
				});
				idle_source.attach (main_context);

				yield;

				var incoming_handler = service.incoming.connect ((c) => {
					pending_stream = c;
					obtain.callback ();
					return true;
				});

				timeout_source = new TimeoutSource.seconds (10);
				timeout_source.set_callback (() => {
					pending_error = new Error.TIMED_OUT ("Unexpectedly timed out while spawning helper process");
					obtain.callback ();
					return false;
				});
				timeout_source.attach (main_context);

				string[] envp = Environ.unset_variable (Environ.get (), "LD_LIBRARY_PATH");

				try {
					string cwd = "/";
					string[] argv = new string[] { "su", "-c", helper_file.path, socket_address };
					bool capture_output = false;
					pending_superprocess = yield SuperSU.spawn (cwd, argv, envp, capture_output, cancellable);
				} catch (Error e) {
					string[] argv = { helper_file.path, socket_address };

					GLib.SpawnFlags flags = GLib.SpawnFlags.LEAVE_DESCRIPTORS_OPEN | /* GLib.SpawnFlags.CLOEXEC_PIPES */ 256;
					GLib.Process.spawn_async (null, argv, envp, flags, null, out pending_pid);
				}

				yield;

				service.disconnect (incoming_handler);
				service.stop ();
				service = null;
				timeout_source.destroy ();
				timeout_source = null;

				if (pending_error == null) {
					pending_connection = yield new DBusConnection (pending_stream, ServerGuid.HOST_SESSION_SERVICE,
						AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS, null, cancellable);
					pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER, DO_NOT_LOAD_PROPERTIES,
						cancellable);
					if (pending_connection.is_closed ())
						throw new Error.NOT_SUPPORTED ("Helper terminated prematurely");
				}
			} catch (GLib.Error e) {
				if (timeout_source != null)
					timeout_source.destroy ();

				if (service != null)
					service.stop ();

				if (e is Error || e is IOError.CANCELLED)
					pending_error = e;
				else
					pending_error = new Error.PERMISSION_DENIED ("%s", e.message);
			}

			if (pending_error == null) {
				superprocess = pending_superprocess;
				process_pid = pending_pid;

				connection = pending_connection;
				connection.on_closed.connect (on_connection_closed);

				assign_helper (new HelperSession (pending_proxy));

				obtain_request.resolve (helper);
				return helper;
			} else {
				if (pending_pid != 0)
					Posix.kill ((Posix.pid_t) pending_pid, Posix.Signal.KILL);

				obtain_request.reject (pending_error);
				obtain_request = null;

				throw_api_error (pending_error);
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			obtain_request = null;

			discard_helper ();

			connection.on_closed.disconnect (on_connection_closed);
			connection = null;

			superprocess = null;
			process_pid = 0;
		}

		private void assign_helper (owned LinuxHelper h) {
			helper = h;
			helper.output.connect (on_helper_output);
			helper.uninjected.connect (on_helper_uninjected);
		}

		private void discard_helper () {
			if (helper == null)
				return;

			var h = helper;
			h.output.disconnect (on_helper_output);
			h.uninjected.disconnect (on_helper_uninjected);
			helper = null;

			lost (h);
		}

		private void on_helper_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_helper_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class HelperSession : Object, LinuxHelper {
		public LinuxRemoteHelper proxy {
			get;
			construct;
		}

		public HelperSession (LinuxRemoteHelper proxy) {
			Object (proxy: proxy);
		}

		construct {
			proxy.output.connect (on_output);
			proxy.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			try {
				yield proxy.stop (cancellable);
			} catch (GLib.Error e) {
			}

			proxy.output.disconnect (on_output);
			proxy.uninjected.disconnect (on_uninjected);
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			try {
				return yield proxy.spawn (path, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.prepare_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.await_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.cancel_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void await_syscall (uint pid, LinuxSyscall mask, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.await_syscall (pid, mask, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume_syscall (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.resume_syscall (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.kill (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void inject_library (uint pid, UnixInputStream library_so, string entrypoint, string data,
				AgentFeatures features, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.inject_library (pid, library_so, entrypoint, data, features, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async IOStream request_control_channel (uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				Socket socket = yield proxy.request_control_channel (id, cancellable);
				return SocketConnection.factory_create_connection (socket);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.demonitor (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, AgentFeatures features,
				Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.demonitor_and_clone_injectee_state (id, clone_id, features, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.recreate_injectee_thread (pid, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class ResourceStore {
		public TemporaryDirectory tempdir {
			get;
			private set;
		}

		public HelperFile? helper32 {
			get;
			private set;
		}

		public HelperFile? helper64 {
			get;
			private set;
		}

		public ResourceStore (TemporaryDirectory tempdir) throws Error {
			this.tempdir = tempdir;

#if HAVE_EMBEDDED_ASSETS
			var blob32 = Frida.Data.Helper.get_frida_helper_32_blob ();
			if (blob32.data.length > 0)
				helper32 = make_temporary_helper ("frida-helper-32", blob32.data);

			var blob64 = Frida.Data.Helper.get_frida_helper_64_blob ();
			if (blob64.data.length > 0)
				helper64 = make_temporary_helper ("frida-helper-64", blob64.data);
#else
			var tpl = PathTemplate (Config.FRIDA_HELPER_PATH);
			string path = tpl.expand ((sizeof (void *) == 8) ? "32" : "64");
			HelperFile file = new InstalledHelperFile.for_path (path);
			if (sizeof (void *) == 8)
				helper32 = file;
			else
				helper64 = file;
#endif
		}

#if HAVE_EMBEDDED_ASSETS
		private HelperFile make_temporary_helper (string name, uint8[] data) throws Error {
			if (MemoryFileDescriptor.is_supported ())
				return new MemoryHelperFile (name, new Bytes.static (data));

			var helper = new TemporaryHelperFile (
				new TemporaryFile.from_stream (name,
					new MemoryInputStream.from_data (data, null),
					tempdir));
			FileUtils.chmod (helper.path, 0700);
			return helper;
		}
#endif
	}

	private class MemoryHelperFile : Object, HelperFile {
		public FileDescriptor fd {
			get;
			construct;
		}

		public string path {
			owned get {
				return "/proc/self/fd/%d".printf (fd.handle);
			}
		}

		public MemoryHelperFile (string name, Bytes bytes) {
			Object (fd: MemoryFileDescriptor.from_bytes (name, bytes));
		}
	}
}

"""

```