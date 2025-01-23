Response:
### 功能归纳

在 `frida.vala` 文件的第2部分中，主要实现了以下功能：

1. **进程管理**：
   - `kill_sync`：同步杀死指定进程。
   - `attach` 和 `attach_sync`：附加到指定进程，创建一个会话（Session）用于后续的调试操作。
   - `inject_library_file` 和 `inject_library_file_sync`：将指定的库文件注入到目标进程中。
   - `inject_library_blob` 和 `inject_library_blob_sync`：将二进制数据（Blob）作为库注入到目标进程中。

2. **会话管理**：
   - `Session` 类：表示一个与目标进程的会话，提供了脚本创建、编译、快照等功能。
   - `create_script` 和 `create_script_sync`：在会话中创建一个新的脚本。
   - `create_script_from_bytes` 和 `create_script_from_bytes_sync`：从二进制数据中创建脚本。
   - `compile_script` 和 `compile_script_sync`：编译脚本并返回编译后的二进制数据。
   - `snapshot_script` 和 `snapshot_script_sync`：生成脚本的快照。

3. **子进程管理**：
   - `enable_child_gating` 和 `enable_child_gating_sync`：启用子进程管理功能，允许监控目标进程的子进程。
   - `disable_child_gating` 和 `disable_child_gating_sync`：禁用子进程管理功能。

4. **通道和服务管理**：
   - `open_channel` 和 `open_channel_sync`：打开一个通道，用于与目标进程进行通信。
   - `open_service` 和 `open_service_sync`：打开一个服务，用于提供额外的功能。

5. **设备管理**：
   - `unpair` 和 `unpair_sync`：解除设备的配对状态。

6. **调试功能**：
   - `resume` 和 `resume_sync`：恢复被中断的会话。
   - `detach` 和 `detach_sync`：从目标进程中分离会话。

### 二进制底层和 Linux 内核相关

- **进程注入**：`inject_library_file` 和 `inject_library_blob` 涉及到将动态库或二进制数据注入到目标进程中。这在 Linux 系统中通常通过 `ptrace` 系统调用实现，`ptrace` 允许一个进程（调试器）控制另一个进程（被调试进程）的执行，并可以修改其内存和寄存器。
  
- **子进程管理**：`enable_child_gating` 和 `disable_child_gating` 涉及到对目标进程的子进程进行监控。在 Linux 中，这通常通过 `fork` 和 `exec` 系统调用来实现，调试器可以通过 `ptrace` 来捕获这些事件。

### LLDB 调试示例

假设我们想要使用 LLDB 来调试 `attach` 函数的行为，以下是一个简单的 LLDB Python 脚本示例：

```python
import lldb

def attach_to_process(pid):
    # 创建一个调试器实例
    debugger = lldb.SBDebugger.Create()
    
    # 创建一个目标
    target = debugger.CreateTarget("")
    
    # 附加到指定进程
    error = lldb.SBError()
    process = target.AttachToProcessWithID(lldb.SBListener(), pid, error)
    
    if error.Success():
        print(f"成功附加到进程 {pid}")
    else:
        print(f"附加失败: {error}")

# 使用示例
attach_to_process(1234)  # 1234 是目标进程的 PID
```

### 逻辑推理与假设输入输出

- **假设输入**：用户调用 `attach_sync(1234)`，其中 `1234` 是目标进程的 PID。
- **假设输出**：如果附加成功，返回一个 `Session` 对象，表示与目标进程的会话。如果附加失败，抛出 `Error` 或 `IOError` 异常。

### 用户常见错误

1. **进程不存在**：用户尝试附加到一个不存在的进程，导致 `attach` 失败。
   - **示例**：`attach_sync(9999)`，但 PID 为 9999 的进程不存在。
   - **错误信息**：`Error: Process not found`

2. **权限不足**：用户尝试附加到一个需要更高权限的进程（如 root 进程），但没有足够的权限。
   - **示例**：普通用户尝试附加到 root 进程。
   - **错误信息**：`Error: Permission denied`

3. **注入失败**：用户尝试注入一个不兼容的库文件或二进制数据，导致注入失败。
   - **示例**：`inject_library_file_sync(1234, "/path/to/invalid_library.so", "entrypoint", "data")`
   - **错误信息**：`Error: Injection failed`

### 用户操作步骤与调试线索

1. **用户操作**：用户调用 `attach_sync(1234)` 附加到目标进程。
2. **调试线索**：
   - 检查目标进程是否存在。
   - 检查用户是否有足够的权限附加到目标进程。
   - 如果附加成功，检查返回的 `Session` 对象是否有效。
   - 如果附加失败，检查错误信息并确定失败原因。

通过这些步骤，用户可以逐步排查问题并找到调试线索。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/frida.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
```