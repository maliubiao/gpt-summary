Response:
### 功能归纳

该源代码文件是 Frida 动态插桩工具的核心部分，主要实现了以下功能：

1. **进程管理**：
   - **`kill_sync`**: 同步杀死指定进程。
   - **`attach`**: 异步附加到指定进程，创建一个会话（`Session`）用于后续的调试和插桩操作。
   - **`attach_sync`**: 同步版本的 `attach` 方法。

2. **库注入**：
   - **`inject_library_file`**: 异步将指定的库文件注入到目标进程中。
   - **`inject_library_file_sync`**: 同步版本的 `inject_library_file` 方法。
   - **`inject_library_blob`**: 异步将二进制数据（`Bytes`）作为库注入到目标进程中。
   - **`inject_library_blob_sync`**: 同步版本的 `inject_library_blob` 方法。

3. **通道与服务管理**：
   - **`open_channel`**: 异步打开一个通道（`IOStream`），用于与目标进程进行通信。
   - **`open_channel_sync`**: 同步版本的 `open_channel` 方法。
   - **`open_service`**: 异步打开一个服务（`Service`），用于与目标进程进行更高级的交互。
   - **`open_service_sync`**: 同步版本的 `open_service` 方法。

4. **设备配对与解配对**：
   - **`unpair`**: 异步解配对设备。
   - **`unpair_sync`**: 同步版本的 `unpair` 方法。

5. **会话管理**：
   - **`Session` 类**: 管理一个与目标进程的会话，支持脚本的创建、编译、执行等操作。
   - **`detach`**: 异步从目标进程中分离会话。
   - **`detach_sync`**: 同步版本的 `detach` 方法。
   - **`resume`**: 异步恢复目标进程的执行。
   - **`resume_sync`**: 同步版本的 `resume` 方法。

6. **脚本管理**：
   - **`create_script`**: 异步创建一个脚本并注入到目标进程中。
   - **`create_script_sync`**: 同步版本的 `create_script` 方法。
   - **`create_script_from_bytes`**: 异步从二进制数据创建脚本并注入到目标进程中。
   - **`create_script_from_bytes_sync`**: 同步版本的 `create_script_from_bytes` 方法。
   - **`compile_script`**: 异步编译脚本并返回编译后的二进制数据。
   - **`compile_script_sync`**: 同步版本的 `compile_script` 方法。
   - **`snapshot_script`**: 异步生成脚本的快照并返回二进制数据。
   - **`snapshot_script_sync`**: 同步版本的 `snapshot_script` 方法。

7. **子进程管理**：
   - **`enable_child_gating`**: 异步启用子进程管理功能。
   - **`enable_child_gating_sync`**: 同步版本的 `enable_child_gating` 方法。
   - **`disable_child_gating`**: 异步禁用子进程管理功能。
   - **`disable_child_gating_sync`**: 同步版本的 `disable_child_gating` 方法。

8. **事件处理**：
   - **`on_spawn_added`**: 处理新进程生成的事件。
   - **`on_spawn_removed`**: 处理进程移除的事件。
   - **`on_child_added`**: 处理子进程添加的事件。
   - **`on_child_removed`**: 处理子进程移除的事件。
   - **`on_process_crashed`**: 处理进程崩溃的事件。
   - **`on_output`**: 处理进程输出的数据。
   - **`on_uninjected`**: 处理库卸载的事件。

### 二进制底层与 Linux 内核相关

- **库注入**：`inject_library_file` 和 `inject_library_blob` 方法涉及到将动态库注入到目标进程的地址空间中。这在 Linux 上通常通过 `ptrace` 系统调用实现，`ptrace` 允许一个进程（调试器）控制另一个进程（被调试进程）的执行，并修改其内存和寄存器。
- **进程管理**：`kill_sync` 方法通过发送 `SIGKILL` 信号来终止目标进程，这是 Linux 内核提供的进程管理功能之一。

### LLDB 调试示例

假设我们想要调试 `attach` 方法，可以使用 LLDB 来设置断点并观察其执行流程。以下是一个 LLDB Python 脚本示例：

```python
import lldb

def attach_to_process(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    
    # 设置断点
    breakpoint = target.BreakpointCreateByName("frida::Device::attach")
    print(f"Breakpoint created at 'frida::Device::attach'")
    
    # 继续执行
    process.Continue()

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.attach_to_process attach_to_process')
    print('The "attach_to_process" command has been installed.')
```

### 逻辑推理与假设输入输出

假设我们调用 `attach` 方法附加到进程 ID 为 `1234` 的进程：

- **输入**：`pid = 1234`
- **输出**：返回一个 `Session` 对象，表示与目标进程的会话。

如果目标进程不存在或权限不足，可能会抛出 `Error` 或 `IOError` 异常。

### 用户常见错误

1. **权限不足**：用户尝试附加到需要更高权限的进程（如 root 进程）时，可能会遇到权限错误。
   - **示例**：`Error: Permission denied`
   - **解决方法**：以 root 权限运行 Frida。

2. **进程不存在**：用户尝试附加到一个不存在的进程 ID。
   - **示例**：`Error: No such process`
   - **解决方法**：确保进程 ID 正确且进程正在运行。

3. **库注入失败**：用户尝试注入的库文件路径不正确或库文件格式不兼容。
   - **示例**：`Error: Failed to inject library`
   - **解决方法**：检查库文件路径和格式，确保库文件与目标进程的架构兼容。

### 用户操作步骤与调试线索

1. **启动 Frida**：用户启动 Frida 并选择目标设备。
2. **选择目标进程**：用户通过 Frida 的 API 选择要附加的进程 ID。
3. **调用 `attach` 方法**：用户调用 `attach` 方法，Frida 开始与目标进程建立会话。
4. **调试线索**：
   - 如果 `attach` 方法失败，用户可以通过日志或调试器查看具体的错误信息。
   - 如果成功，用户可以通过返回的 `Session` 对象进行进一步的调试和插桩操作。

通过这些步骤，用户可以逐步定位问题并进行调试。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/frida.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能

"""

		public void kill_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<KillTask> ();
			task.pid = pid;
			task.execute (cancellable);
		}

		private class KillTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.kill (pid, cancellable);
			}
		}

		public async Session attach (uint pid, SessionOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			SessionOptions opts = (options != null) ? options : new SessionOptions ();

			var attach_request = new Promise<Session> ();
			pending_attach_requests.add (attach_request);

			Session session = null;
			try {
				var host_session = yield get_host_session (cancellable);

				var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

				AgentSessionId id;
				try {
					id = yield host_session.attach (pid, raw_options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				try {
					session = new Session (this, pid, id, opts);
					session.active_session = yield provider.link_agent_session (host_session, id, session, cancellable);
					agent_sessions[id] = session;

					attach_request.resolve (session);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			} catch (Error e) {
				attach_request.reject (e);
				throw e;
			} catch (IOError e) {
				attach_request.reject (e);
				throw e;
			} finally {
				pending_attach_requests.remove (attach_request);
			}

			return session;
		}

		public Session attach_sync (uint pid, SessionOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<AttachTask> ();
			task.pid = pid;
			task.options = options;
			return task.execute (cancellable);
		}

		private class AttachTask : DeviceTask<Session> {
			public uint pid;
			public SessionOptions? options;

			protected override async Session perform_operation () throws Error, IOError {
				return yield parent.attach (pid, options, cancellable);
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				var id = yield host_session.inject_library_file (pid, path, entrypoint, data, cancellable);

				return id.handle;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryFileTask> ();
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryFileTask : DeviceTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_file (pid, path, entrypoint, data, cancellable);
			}
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				var id = yield host_session.inject_library_blob (pid, blob.get_data (), entrypoint, data, cancellable);

				return id.handle;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<InjectLibraryBlobTask> ();
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryBlobTask : DeviceTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var channel_provider = provider as HostChannelProvider;
			if (channel_provider == null)
				throw new Error.NOT_SUPPORTED ("Channels are not supported by this device");

			return yield channel_provider.open_channel (address, cancellable);
		}

		public IOStream open_channel_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<OpenChannelTask> ();
			task.address = address;
			return task.execute (cancellable);
		}

		private class OpenChannelTask : DeviceTask<IOStream> {
			public string address;

			protected override async IOStream perform_operation () throws Error, IOError {
				return yield parent.open_channel (address, cancellable);
			}
		}

		public async Service open_service (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var service_provider = provider as HostServiceProvider;
			if (service_provider == null)
				throw new Error.NOT_SUPPORTED ("Services are not supported by this device");

			var service = yield service_provider.open_service (address, cancellable);
			service.close.connect (on_service_closed);
			services.add (service);

			return service;
		}

		public Service open_service_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<OpenServiceTask> ();
			task.address = address;
			return task.execute (cancellable);
		}

		private class OpenServiceTask : DeviceTask<Service> {
			public string address;

			protected override async Service perform_operation () throws Error, IOError {
				return yield parent.open_service (address, cancellable);
			}
		}

		private void on_service_closed (Service service) {
			services.remove (service);
		}

		public async void unpair (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var pairable = provider as Pairable;
			if (pairable == null)
				throw new Error.NOT_SUPPORTED ("Pairing functionality is not supported by this device");

			yield pairable.unpair (cancellable);
		}

		public void unpair_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<UnpairTask> ().execute (cancellable);
		}

		private class UnpairTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.unpair (cancellable);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Device is gone");
		}

		internal async HostSession get_host_session (Cancellable? cancellable) throws Error, IOError {
			while (host_session_request != null) {
				try {
					return yield host_session_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			host_session_request = new Promise<HostSession> ();

			try {
				var session = yield provider.create (host_session_options, cancellable);
				attach_host_session (session);

				current_host_session = session;
				host_session_request.resolve (session);

				return session;
			} catch (GLib.Error e) {
				host_session_request.reject (e);
				host_session_request = null;

				throw_api_error (e);
			}
		}

		private void on_host_session_detached (HostSession session) {
			if (session != current_host_session)
				return;

			_bus._detach.begin (session);

			detach_host_session (session);

			current_host_session = null;
			host_session_request = null;
		}

		private void attach_host_session (HostSession session) {
			session.spawn_added.connect (on_spawn_added);
			session.spawn_removed.connect (on_spawn_removed);
			session.child_added.connect (on_child_added);
			session.child_removed.connect (on_child_removed);
			session.process_crashed.connect (on_process_crashed);
			session.output.connect (on_output);
			session.uninjected.connect (on_uninjected);
		}

		private void detach_host_session (HostSession session) {
			session.spawn_added.disconnect (on_spawn_added);
			session.spawn_removed.disconnect (on_spawn_removed);
			session.child_added.disconnect (on_child_added);
			session.child_removed.disconnect (on_child_removed);
			session.process_crashed.disconnect (on_process_crashed);
			session.output.disconnect (on_output);
			session.uninjected.disconnect (on_uninjected);
		}

		internal async void _do_close (SessionDetachReason reason, bool may_block, Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			try {
				foreach (var service in services.to_array ())
					yield service.cancel (cancellable);
				services.clear ();

				while (!pending_detach_requests.is_empty) {
					var iterator = pending_detach_requests.entries.iterator ();
					iterator.next ();
					var entry = iterator.get ();

					var session_id = entry.key;
					var detach_request = entry.value;

					detach_request.resolve (true);
					pending_detach_requests.unset (session_id);
				}

				while (!pending_attach_requests.is_empty) {
					var iterator = pending_attach_requests.iterator ();
					iterator.next ();
					var attach_request = iterator.get ();
					try {
						yield attach_request.future.wait_async (cancellable);
					} catch (GLib.Error e) {
						cancellable.set_error_if_cancelled ();
					}
				}

				if (host_session_request != null) {
					try {
						yield get_host_session (cancellable);
					} catch (Error e) {
					}
				}

				var no_crash = CrashInfo.empty ();
				foreach (var session in agent_sessions.values.to_array ())
					yield session._do_close (reason, no_crash, may_block, cancellable);
				agent_sessions.clear ();

				provider.host_session_detached.disconnect (on_host_session_detached);
				provider.agent_session_detached.disconnect (on_agent_session_detached);

				if (current_host_session != null) {
					detach_host_session (current_host_session);

					if (may_block) {
						try {
							yield provider.destroy (current_host_session, cancellable);
						} catch (Error e) {
						}
					}

					current_host_session = null;
					host_session_request = null;
				}

				if (manager != null)
					manager._release_device (this);

				lost ();

				close_request.resolve (true);
			} catch (IOError e) {
				close_request.reject (e);
				close_request = null;
				throw e;
			}
		}

		internal async void _release_session (Session session, bool may_block, Cancellable? cancellable) throws IOError {
			AgentSessionId? session_id = null;
			foreach (var entry in agent_sessions.entries) {
				if (entry.value == session) {
					session_id = entry.key;
					break;
				}
			}
			assert (session_id != null);
			agent_sessions.unset (session_id);

			if (may_block) {
				var detach_request = new Promise<bool> ();

				pending_detach_requests[session_id] = detach_request;

				try {
					yield detach_request.future.wait_async (cancellable);
				} catch (Error e) {
					assert_not_reached ();
				}
			}
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			var session = agent_sessions[id];
			if (session != null)
				session._on_detached (reason, crash);

			Promise<bool> detach_request;
			if (pending_detach_requests.unset (id, out detach_request))
				detach_request.resolve (true);
		}

		private void on_spawn_added (HostSpawnInfo info) {
			spawn_added (Spawn.from_info (info));
		}

		private void on_spawn_removed (HostSpawnInfo info) {
			spawn_removed (Spawn.from_info (info));
		}

		private void on_child_added (HostChildInfo info) {
			child_added (Child.from_info (info));
		}

		private void on_child_removed (HostChildInfo info) {
			child_removed (Child.from_info (info));
		}

		private void on_process_crashed (CrashInfo info) {
			process_crashed (Crash.from_info (info));
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, new Bytes (data));
		}

		private void on_uninjected (InjectorPayloadId id) {
			uninjected (id.handle);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class DeviceTask<T> : AsyncTask<T> {
			public weak Device parent {
				get;
				construct;
			}
		}
	}

	public enum DeviceType {
		LOCAL,
		REMOTE,
		USB;

		public static DeviceType from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<DeviceType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<DeviceType> (this);
		}
	}

	public class RemoteDeviceOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? origin {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}

		public int keepalive_interval {
			get;
			set;
			default = -1;
		}
	}

	public class ApplicationList : Object {
		private Gee.List<Application> items;

		internal ApplicationList (Gee.List<Application> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Application get (int index) {
			return items.get (index);
		}
	}

	public class Application : Object {
		public string identifier {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Application (string identifier, string name, uint pid, HashTable<string, Variant> parameters) {
			Object (identifier: identifier, name: name, pid: pid, parameters: parameters);
		}
	}

	public class ProcessList : Object {
		private Gee.List<Process> items;

		internal ProcessList (Gee.List<Process> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Process get (int index) {
			return items.get (index);
		}
	}

	public class Process : Object {
		public uint pid {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Process (uint pid, string name, HashTable<string, Variant> parameters) {
			Object (pid: pid, name: name, parameters: parameters);
		}
	}

	public class ProcessMatchOptions : Object {
		public int timeout {
			get;
			set;
			default = 0;
		}

		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}
	}

	public class SpawnOptions : Object {
		public string[]? argv {
			get;
			set;
		}

		public string[]? envp {
			get;
			set;
		}

		public string[]? env {
			get;
			set;
		}

		public string? cwd {
			get;
			set;
		}

		public Stdio stdio {
			get;
			set;
			default = INHERIT;
		}

		public HashTable<string, Variant> aux {
			get;
			set;
			default = make_parameters_dict ();
		}
	}

	public class SpawnList : Object {
		private Gee.List<Spawn> items;

		internal SpawnList (Gee.List<Spawn> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Spawn get (int index) {
			return items.get (index);
		}
	}

	public class Spawn : Object {
		public uint pid {
			get;
			construct;
		}

		public string? identifier {
			get;
			construct;
		}

		internal Spawn (uint pid, string? identifier) {
			Object (
				pid: pid,
				identifier: identifier
			);
		}

		internal static Spawn from_info (HostSpawnInfo info) {
			var identifier = info.identifier;
			return new Spawn (info.pid, (identifier.length > 0) ? identifier : null);
		}
	}

	public class ChildList : Object {
		private Gee.List<Child> items;

		internal ChildList (Gee.List<Child> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Child get (int index) {
			return items.get (index);
		}
	}

	public class Child : Object {
		public uint pid {
			get;
			construct;
		}

		public uint parent_pid {
			get;
			construct;
		}

		public ChildOrigin origin {
			get;
			construct;
		}

		public string? identifier {
			get;
			construct;
		}

		public string? path {
			get;
			construct;
		}

		public string[]? argv {
			get;
			construct;
		}

		public string[]? envp {
			get;
			construct;
		}

		internal Child (uint pid, uint parent_pid, ChildOrigin origin, string? identifier, string? path, string[]? argv,
				string[]? envp) {
			Object (
				pid: pid,
				parent_pid: parent_pid,
				origin: origin,
				identifier: identifier,
				path: path,
				argv: argv,
				envp: envp
			);
		}

		internal static Child from_info (HostChildInfo info) {
			var identifier = info.identifier;
			var path = info.path;
			return new Child (
				info.pid,
				info.parent_pid,
				info.origin,
				(identifier.length > 0) ? identifier : null,
				(path.length > 0) ? path : null,
				info.has_argv ? info.argv : null,
				info.has_envp ? info.envp : null
			);
		}
	}

	public class Crash : Object {
		public uint pid {
			get;
			construct;
		}

		public string process_name {
			get;
			construct;
		}

		public string summary {
			get;
			construct;
		}

		public string report {
			get;
			construct;
		}

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Crash (uint pid, string process_name, string summary, string report, HashTable<string, Variant> parameters) {
			Object (
				pid: pid,
				process_name: process_name,
				summary: summary,
				report: report,
				parameters: parameters
			);
		}

		internal static Crash? from_info (CrashInfo info) {
			if (info.pid == 0)
				return null;
			return new Crash (
				info.pid,
				info.process_name,
				info.summary,
				info.report,
				info.parameters
			);
		}
	}

	public class Bus : Object {
		public signal void detached ();
		public signal void message (string json, Bytes? data);

		public weak Device device {
			get;
			construct;
		}

		private Promise<BusSession>? attach_request;

		private BusSession? active_session;
		private Cancellable io_cancellable = new Cancellable ();

		internal Bus (Device device) {
			Object (device: device);
		}

		public bool is_detached () {
			return attach_request == null;
		}

		public async void attach (Cancellable? cancellable = null) throws Error, IOError {
			while (attach_request != null) {
				try {
					yield attach_request.future.wait_async (cancellable);
					return;
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			attach_request = new Promise<BusSession> ();

			try {
				var host_session = yield device.get_host_session (cancellable);

				DBusProxy proxy = host_session as DBusProxy;
				if (proxy == null)
					throw new Error.NOT_SUPPORTED ("Bus is not available on this device");

				try {
					active_session = yield proxy.g_connection.get_proxy (null, ObjectPath.BUS_SESSION,
						DO_NOT_LOAD_PROPERTIES, cancellable);
					active_session.message.connect (on_message);

					yield active_session.attach (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				attach_request.resolve (active_session);
			} catch (GLib.Error e) {
				attach_request.reject (e);
				attach_request = null;

				throw_api_error (e);
			}
		}

		public void attach_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<AttachTask> ().execute (cancellable);
		}

		private class AttachTask : BusTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.attach (cancellable);
			}
		}

		internal async void _detach (HostSession dead_host_session) {
			if (attach_request == null)
				return;

			DBusConnection dead_connection = ((DBusProxy) dead_host_session).g_connection;

			io_cancellable.cancel ();
			io_cancellable = new Cancellable ();

			while (attach_request != null) {
				try {
					var some_session = yield attach_request.future.wait_async (null);
					if (((DBusProxy) some_session).g_connection == dead_connection) {
						some_session.message.disconnect (on_message);
						active_session = null;
						attach_request = null;
					} else {
						return;
					}
				} catch (GLib.Error e) {
				}
			}

			detached ();
		}

		public void post (string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_post (json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_post (json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_post (string json, Bytes? data) {
			if (active_session == null)
				return;
			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];
			active_session.post.begin (json, has_data, data_param, io_cancellable);
		}

		private void on_message (string json, bool has_data, uint8[] data) {
			message (json, has_data ? new Bytes (data) : null);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class BusTask<T> : AsyncTask<T> {
			public weak Bus parent {
				get;
				construct;
			}
		}
	}

	public interface Service : Object {
		public signal void close ();
		public signal void message (Variant message);

		public abstract bool is_closed ();

		public abstract async void activate (Cancellable? cancellable = null) throws Error, IOError;

		public void activate_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<ActivateTask> ().execute (cancellable);
		}

		private class ActivateTask : ServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.activate (cancellable);
			}
		}

		public abstract async void cancel (Cancellable? cancellable = null) throws IOError;

		public void cancel_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<CancelTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CancelTask : ServiceTask<void> {
			protected override async void perform_operation () throws IOError {
				yield parent.cancel (cancellable);
			}
		}

		public abstract async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError;

		public Variant request_sync (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RequestTask> () as RequestTask;
			task.parameters = parameters;
			return task.execute (cancellable);
		}

		private class RequestTask : ServiceTask<Variant> {
			public Variant parameters;

			protected override async Variant perform_operation () throws Error, IOError {
				return yield parent.request (parameters, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ServiceTask<T> : AsyncTask<T> {
			public weak Service parent {
				get;
				construct;
			}
		}
	}

	public class Session : Object, AgentMessageSink {
		public signal void detached (SessionDetachReason reason, Crash? crash);

		public uint pid {
			get;
			construct;
		}

		public uint persist_timeout {
			get;
			construct;
		}

		private AgentSessionId id;
		private unowned Device device;

		private State state = ATTACHED;
		private Promise<bool> close_request;

		internal AgentSession active_session;
		private AgentSession? obsolete_session;

		private uint last_rx_batch_id = 0;
		private Gee.LinkedList<PendingMessage> pending_messages = new Gee.LinkedList<PendingMessage> ();
		private int next_serial = 1;
		private uint pending_deliveries = 0;
		private Cancellable delivery_cancellable = new Cancellable ();

		private Gee.HashMap<AgentScriptId?, Script> scripts =
			new Gee.HashMap<AgentScriptId?, Script> (AgentScriptId.hash, AgentScriptId.equal);

		private PeerOptions? nice_options;
#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private SctpConnection? nice_iostream;
		private DBusConnection? nice_connection;
		private uint nice_registration_id;
		private Cancellable? nice_cancellable;

		private MainContext? frida_context;
		private MainContext? dbus_context;
#endif

		private enum State {
			ATTACHED,
			INTERRUPTED,
			DETACHED,
		}

		internal Session (Device device, uint pid, AgentSessionId id, SessionOptions options) {
			Object (pid: pid, persist_timeout: options.persist_timeout);

			this.id = id;
			this.device = device;
		}

		public bool is_detached () {
			return state != ATTACHED;
		}

		public async void detach (Cancellable? cancellable = null) throws IOError {
			yield _do_close (APPLICATION_REQUESTED, CrashInfo.empty (), true, cancellable);
		}

		public void detach_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<DetachTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class DetachTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.detach (cancellable);
			}
		}

		public async void resume (Cancellable? cancellable = null) throws Error, IOError {
			switch (state) {
				case ATTACHED:
					return;
				case INTERRUPTED:
					break;
				case DETACHED:
					throw new Error.INVALID_OPERATION ("Session is gone");
			}

			DBusConnection old_connection = ((DBusProxy) active_session).g_connection;
			if (old_connection.is_closed ()) {
				var host_session = yield device.get_host_session (cancellable);

				try {
					yield host_session.reattach (id, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var agent_session = yield device.provider.link_agent_session (host_session, id, this, cancellable);

				begin_migration (agent_session);
			}

			if (nice_options != null) {
				yield do_setup_peer_connection (nice_options, cancellable);
			}

			uint last_tx_batch_id;
			try {
				yield active_session.resume (last_rx_batch_id, cancellable, out last_tx_batch_id);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			if (last_tx_batch_id != 0) {
				PendingMessage? m;
				while ((m = pending_messages.peek ()) != null && m.delivery_attempts > 0 && m.serial <= last_tx_batch_id) {
					pending_messages.poll ();
				}
			}

			delivery_cancellable = new Cancellable ();
			state = ATTACHED;

			maybe_deliver_pending_messages ();
		}

		public void resume_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<ResumeTask> ().execute (cancellable);
		}

		private class ResumeTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.resume (cancellable);
			}
		}

		public async void enable_child_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield active_session.enable_child_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void enable_child_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EnableChildGatingTask> ().execute (cancellable);
		}

		private class EnableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_child_gating (cancellable);
			}
		}

		public async void disable_child_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield active_session.disable_child_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_child_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableChildGatingTask> ().execute (cancellable);
		}

		private class DisableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_child_gating (cancellable);
			}
		}

		public async Script create_script (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			AgentScriptId script_id;
			try {
				script_id = yield active_session.create_script (source, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_sync (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CreateScriptTask> ();
			task.source = source;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CreateScriptTask : SessionTask<Script> {
			public string source;
			public ScriptOptions? options;

			protected override async Script perform_operation () throws Error, IOError {
				return yield parent.create_script (source, options, cancellable);
			}
		}

		public async Script create_script_from_bytes (Bytes bytes, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			AgentScriptId script_id;
			try {
				script_id = yield active_session.create_script_from_bytes (bytes.get_data (), raw_options,
					cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_from_bytes_sync (Bytes bytes, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CreateScriptFromBytesTask> ();
			task.bytes = bytes;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CreateScriptFromBytesTask : SessionTask<Script> {
			public Bytes bytes;
			public ScriptOptions? options;

			protected override async Script perform_operation () throws Error, IOError {
				return yield parent.create_script_from_bytes (bytes, options, cancellable);
			}
		}

		public async Bytes compile_script (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			uint8[] data;
			try {
				data = yield active_session.compile_script (source, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new Bytes (data);
		}

		public Bytes compile_script_sync (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CompileScriptTask> ();
			task.source = source;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CompileScriptTask : SessionTask<Bytes> {
			public string source;
			public ScriptOptions? options;

			protected override async Bytes perform_operation () throws Error, IOError {
				return yield parent.compile_script (source, options, cancellable);
			}
		}

		public async Bytes snapshot_script (string embed_script, SnapshotOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			uint8[] data;
			try {
				data = yield active_session.snapshot_script (embed_script, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new Bytes (data);
		}

		public Bytes snapshot_script_sync (string embed_script, SnapshotOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<SnapshotScriptTask> ();
			task.embed_script = embed_script;
			task.options = options;
			return task.execute (cancellable);
		}

		private class SnapshotScriptTask : SessionTask<Bytes> {
			public string embed_script;
			public SnapshotOptions? options;

			protected override async Bytes perform_operation () throws Error, IOError {
				return yield pare
"""


```