Response:
### 功能归纳

`host-session-service.vala` 是 Frida 动态插桩工具的核心部分，主要负责管理主机会话（Host Session）和代理会话（Agent Session）的生命周期。以下是该文件的主要功能：

1. **主机会话管理**：
   - `HostSessionService` 类负责管理多个后端（`HostSessionBackend`），这些后端用于与不同的目标设备或进程进行通信。
   - 支持多种后端类型，如本地后端（`LocalBackend`）、USB 后端（`FruityBackend`、`DroidyBackend`）、Socket 后端（`SocketBackend`）等。
   - 提供了启动（`start`）和停止（`stop`）主机会话服务的方法。

2. **代理会话管理**：
   - `HostSessionProvider` 接口定义了创建和销毁代理会话的方法。
   - `BaseDBusHostSession` 类实现了 `HostSession` 和 `AgentController` 接口，负责管理代理会话的生命周期，包括创建、销毁、链接和取消链接代理会话。

3. **进程管理**：
   - 提供了对目标进程的管理功能，如枚举进程（`enumerate_processes`）、枚举应用程序（`enumerate_applications`）、获取前台应用程序（`get_frontmost_application`）等。
   - 支持进程的生成（`spawn`）、恢复（`resume`）、终止（`kill`）等操作。

4. **注入管理**：
   - 提供了注入库文件（`inject_library_file`）和注入库二进制数据（`inject_library_blob`）的功能，用于将 Frida 的代理代码注入到目标进程中。
   - 支持在目标进程中创建代理线程（`recreate_agent_thread`）。

5. **子进程管理**：
   - 提供了对子进程的管理功能，如准备 fork（`prepare_to_fork`）、准备 specialize（`prepare_to_specialize`）等。
   - 支持子进程的生成、恢复、终止等操作。

6. **信号和事件处理**：
   - 提供了多个信号（`signal`）用于处理会话的可用性、不可用性、会话分离等事件。
   - 支持处理子进程的生成、恢复、终止等事件。

### 二进制底层与 Linux 内核相关

1. **进程注入**：
   - 在 Linux 系统中，Frida 使用 `ptrace` 系统调用来附加到目标进程，并通过 `mmap` 和 `mprotect` 等系统调用来在目标进程中分配内存并设置内存保护属性。
   - 注入的库文件或二进制数据会被加载到目标进程的地址空间中，并通过 `dlopen` 和 `dlsym` 等函数来加载和执行。

2. **子进程管理**：
   - 在 Linux 系统中，Frida 使用 `fork` 和 `exec` 系统调用来生成和管理子进程。
   - 通过 `socketpair` 创建 Unix 域套接字对，用于在父进程和子进程之间进行通信。

### LLDB 调试示例

假设我们想要调试 `HostSessionService` 的 `start` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 设置断点
b Frida.HostSessionService.start

# 运行程序
run

# 当断点命中时，查看变量
frame variable

# 继续执行
continue
```

#### LLDB Python 脚本

```python
import lldb

def start_debugging(pid):
    # 创建调试器实例
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)

    # 附加到目标进程
    target = debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)

    # 设置断点
    breakpoint = target.BreakpointCreateByName("Frida.HostSessionService.start", target.GetExecutable().GetFilename())
    print(f"Breakpoint created at: {breakpoint}")

    # 运行程序
    process.Continue()

    # 等待断点命中
    listener = lldb.SBListener("listener")
    event = lldb.SBEvent()
    while True:
        if listener.WaitForEvent(1, event):
            if lldb.SBProcess.EventIsProcessEvent(event):
                state = lldb.SBProcess.GetStateFromEvent(event)
                if state == lldb.eStateStopped:
                    thread = process.GetSelectedThread()
                    frame = thread.GetSelectedFrame()
                    print(f"Stopped at: {frame}")
                    break

    # 查看变量
    for var in frame.variables:
        print(f"{var.name}: {var.value}")

    # 继续执行
    process.Continue()

# 使用示例
start_debugging(1234)
```

### 假设输入与输出

假设我们调用 `HostSessionService` 的 `start` 方法，输入为 `null`，输出为 `void`。

- **输入**：`null`（无输入参数）
- **输出**：`void`（无返回值）

### 常见使用错误

1. **未正确初始化后端**：
   - 用户可能忘记添加必要的后端（如 `LocalBackend` 或 `SocketBackend`），导致无法与目标设备或进程通信。
   - **示例**：用户只添加了 `SocketBackend`，但目标设备需要通过 USB 连接，导致无法建立会话。

2. **未正确处理会话生命周期**：
   - 用户可能在会话未完全启动或停止时尝试进行操作，导致未定义行为或崩溃。
   - **示例**：用户在调用 `start` 方法后立即调用 `stop` 方法，导致会话未完全启动就被停止。

3. **未正确处理子进程**：
   - 用户可能在子进程未完全生成或恢复时尝试进行操作，导致子进程无法正常运行。
   - **示例**：用户在调用 `prepare_to_fork` 后未等待子进程生成完成，导致子进程无法正常启动。

### 用户操作步骤

1. **初始化 `HostSessionService`**：
   - 用户创建一个 `HostSessionService` 实例，并添加必要的后端（如 `LocalBackend` 或 `SocketBackend`）。

2. **启动会话服务**：
   - 用户调用 `start` 方法启动会话服务，等待所有后端初始化完成。

3. **创建代理会话**：
   - 用户通过 `HostSessionProvider` 接口创建代理会话，并链接到目标进程。

4. **管理进程**：
   - 用户通过 `HostSession` 接口管理目标进程，如生成、恢复、终止进程等。

5. **注入库文件或二进制数据**：
   - 用户通过 `inject_library_file` 或 `inject_library_blob` 方法将 Frida 的代理代码注入到目标进程中。

6. **处理子进程**：
   - 用户通过 `prepare_to_fork` 或 `prepare_to_specialize` 方法管理子进程，并处理子进程的生成、恢复、终止等操作。

7. **停止会话服务**：
   - 用户调用 `stop` 方法停止会话服务，释放所有资源。

### 调试线索

1. **会话启动失败**：
   - 检查是否添加了正确的后端，并确保后端已正确初始化。
   - 使用 LLDB 调试 `start` 方法，查看是否有异常抛出。

2. **代理会话无法创建**：
   - 检查目标进程是否已正确附加，并确保目标进程已准备好接受代理会话。
   - 使用 LLDB 调试 `create` 方法，查看是否有异常抛出。

3. **注入失败**：
   - 检查目标进程的内存布局，并确保注入的库文件或二进制数据已正确加载。
   - 使用 LLDB 调试 `inject_library_file` 或 `inject_library_blob` 方法，查看是否有异常抛出。

4. **子进程无法生成**：
   - 检查父进程是否已正确准备 fork 或 specialize，并确保子进程已正确生成。
   - 使用 LLDB 调试 `prepare_to_fork` 或 `prepare_to_specialize` 方法，查看是否有异常抛出。

通过以上步骤和调试线索，用户可以逐步排查问题并找到解决方案。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/host-session-service.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
namespace Frida {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		private delegate void NotifyCompleteFunc ();

		public HostSessionService.with_default_backends () {
			add_local_backends ();
#if !IOS && !ANDROID && !TVOS
#if HAVE_FRUITY_BACKEND
			add_backend (new FruityHostSessionBackend ());
#endif
#if HAVE_DROIDY_BACKEND
			add_backend (new DroidyHostSessionBackend ());
#endif
#endif
#if HAVE_SOCKET_BACKEND
			add_backend (new SocketHostSessionBackend ());
#endif
#if HAVE_BAREBONE_BACKEND
			add_backend (new BareboneHostSessionBackend ());
#endif
		}

		public HostSessionService.with_local_backend_only () {
			add_local_backends ();
		}

		public HostSessionService.with_socket_backend_only () {
#if HAVE_SOCKET_BACKEND
			add_backend (new SocketHostSessionBackend ());
#endif
		}

		private void add_local_backends () {
#if HAVE_LOCAL_BACKEND
#if WINDOWS
			add_backend (new WindowsHostSessionBackend ());
#endif
#if DARWIN
			add_backend (new DarwinHostSessionBackend ());
#endif
#if LINUX
			add_backend (new LinuxHostSessionBackend ());
#endif
#if FREEBSD
			add_backend (new FreebsdHostSessionBackend ());
#endif
#if QNX
			add_backend (new QnxHostSessionBackend ());
#endif
#endif
		}

		public async void start (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					start.callback ();
			};

			foreach (var backend in backends)
				perform_start.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					stop.callback ();
			};

			foreach (var backend in backends)
				perform_stop.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;
		}

		private async void perform_start (HostSessionBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.start (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private async void perform_stop (HostSessionBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.stop (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		public void add_backend (HostSessionBackend backend) {
			backends.add (backend);
			backend.provider_available.connect ((provider) => {
				provider_available (provider);
			});
			backend.provider_unavailable.connect ((provider) => {
				provider_unavailable (provider);
			});
		}

		public void remove_backend (HostSessionBackend backend) {
			backends.remove (backend);
		}
	}

	public interface HostSessionProvider : Object {
		public abstract string id {
			get;
		}

		public abstract string name {
			get;
		}

		public abstract Variant? icon {
			get;
		}

		public abstract HostSessionProviderKind kind {
			get;
		}

		public abstract async HostSession create (HostSessionOptions? options = null,
			Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void destroy (HostSession session, Cancellable? cancellable = null) throws Error, IOError;
		public signal void host_session_detached (HostSession session);

		public abstract async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
			Cancellable? cancellable = null) throws Error, IOError;
		public signal void agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash);
	}

	public enum HostSessionProviderKind {
		LOCAL,
		REMOTE,
		USB
	}

	public class HostSessionOptions : Object {
		public Gee.Map<string, Value?> map {
			get;
			set;
			default = new Gee.HashMap<string, Value?> ();
		}
	}

	public interface HostChannelProvider : Object {
		public abstract async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError;
	}

	public interface HostServiceProvider : Object {
		public abstract async Service open_service (string address, Cancellable? cancellable = null) throws Error, IOError;
	}

	public interface Pairable : Object {
		public abstract async void unpair (Cancellable? cancellable = null) throws Error, IOError;
	}

	public interface HostSessionBackend : Object {
		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public abstract async void start (Cancellable? cancellable = null) throws IOError;
		public abstract async void stop (Cancellable? cancellable = null) throws IOError;
	}

	public abstract class BaseDBusHostSession : Object, HostSession, AgentController {
		private Gee.HashMap<uint, Cancellable> pending_establish_ops = new Gee.HashMap<uint, Cancellable> ();

		private Gee.HashMap<uint, Future<AgentEntry>> agent_entries = new Gee.HashMap<uint, Future<AgentEntry>> ();

		private Gee.HashMap<AgentSessionId?, AgentSessionEntry> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.HashMap<HostChildId?, ChildEntry> child_entries =
			new Gee.HashMap<HostChildId?, ChildEntry> (HostChildId.hash, HostChildId.equal);
		private uint next_host_child_id = 1;
		private Gee.HashMap<uint, HostChildInfo?> pending_children = new Gee.HashMap<uint, HostChildInfo?> ();
		private Gee.HashMap<uint, SpawnAckRequest> pending_acks = new Gee.HashMap<uint, SpawnAckRequest> ();
		private Promise<bool> pending_children_gc_request;
		private Source pending_children_gc_timer;

		protected Injector injector;
		protected Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		protected Cancellable io_cancellable = new Cancellable ();

		public virtual async void preload (Cancellable? cancellable) throws Error, IOError {
		}

		public virtual async void close (Cancellable? cancellable) throws IOError {
			if (pending_children_gc_timer != null) {
				pending_children_gc_timer.destroy ();
				pending_children_gc_timer = null;
			}

			if (pending_children_gc_request != null)
				yield garbage_collect_pending_children (cancellable);

			foreach (var ack_request in pending_acks.values)
				ack_request.complete ();
			pending_acks.clear ();

			while (!agent_entries.is_empty) {
				var iterator = agent_entries.values.iterator ();
				iterator.next ();
				var entry_future = iterator.get ();
				try {
					var entry = yield entry_future.wait_async (cancellable);

					var resume_request = entry.resume_request;
					if (resume_request != null) {
						resume_request.resolve (true);
						entry.resume_request = null;
					}

					yield destroy (entry, APPLICATION_REQUESTED, cancellable);
				} catch (Error e) {
				}
			}

			io_cancellable.cancel ();
		}

		protected abstract async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
			out DBusConnection connection) throws Error, IOError;

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			return compute_system_parameters ();
		}

		public abstract async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
			Cancellable? cancellable) throws Error, IOError;

		public abstract async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
			Cancellable? cancellable) throws Error, IOError;

		public abstract async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
			Cancellable? cancellable) throws Error, IOError;

		public abstract async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError;

		public abstract async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError;

		public abstract async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError;

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var result = new HostChildInfo[pending_children.size];
			var index = 0;
			foreach (var child in pending_children.values)
				result[index++] = child;
			return result;
		}

		public abstract async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError;

		protected virtual bool try_handle_child (HostChildInfo info) {
			return false;
		}

		protected virtual void notify_child_resumed (uint pid) {
		}

		protected virtual void notify_child_gating_changed (uint pid, uint subscriber_count) {
		}

		protected virtual async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
		}

		protected virtual async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected virtual async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected abstract bool process_is_alive (uint pid);

		public abstract async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError;

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			if (yield try_resume_child (pid, cancellable))
				return;

			yield perform_resume (pid, cancellable);
		}

		private async bool try_resume_child (uint pid, Cancellable? cancellable) throws Error, IOError {
			HostChildInfo? info;
			if (pending_children.unset (pid, out info))
				child_removed (info);

			SpawnAckRequest ack_request;
			if (pending_acks.unset (pid, out ack_request)) {
				try {
					if (ack_request.start_state == RUNNING)
						yield perform_resume (pid, cancellable);
				} finally {
					ack_request.complete ();
				}

				notify_child_resumed (pid);

				return true;
			}

			var entry_future = agent_entries[pid];
			if (entry_future == null || !entry_future.ready)
				return false;

			var entry = entry_future.value;

			var resume_request = entry.resume_request;
			if (resume_request == null)
				return false;

			resume_request.resolve (true);
			entry.resume_request = null;

			if (entry.sessions.is_empty) {
				unload_and_destroy.begin (entry, APPLICATION_REQUESTED);
			}

			notify_child_resumed (pid);

			return true;
		}

		protected abstract async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError;

		protected bool still_attached_to (uint pid) {
			return agent_entries.has_key (pid);
		}

		public abstract async void kill (uint pid, Cancellable? cancellable) throws Error, IOError;

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var raw_opts = options;
			var opts = SessionOptions._deserialize (raw_opts);

			if (opts.realm == EMULATED) {
				if (opts.emulated_agent_path == null) {
					opts.emulated_agent_path = get_emulated_agent_path (pid);
					raw_opts = opts._serialize ();
				}
			}

			var entry = yield establish (pid, raw_opts, cancellable);

			var id = AgentSessionId.generate ();
			entry.sessions.add (id);

			try {
				yield entry.provider.open (id, raw_opts, cancellable);
			} catch (GLib.Error e) {
				entry.sessions.remove (id);

				throw new Error.PROTOCOL ("%s", e.message);
			}

			agent_sessions[id] = new AgentSessionEntry (entry.connection);

			return id;
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		private async AgentEntry establish (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			while (agent_entries.has_key (pid)) {
				var future = agent_entries[pid];
				try {
					return yield future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			var promise = new Promise<AgentEntry> ();
			agent_entries[pid] = promise.future;

			AgentEntry entry = null;
			CancellableSource? cancel_source = null;
			try {
				DBusConnection connection;
				AgentSessionProvider provider;

				if (pid == 0) {
					provider = yield create_system_session_provider (cancellable, out connection);
					entry = new AgentEntry (pid, null, connection, provider);
				} else {
					yield wait_for_uninject_of_pid (pid, cancellable);

					var io_cancellable = new Cancellable ();
					pending_establish_ops[pid] = io_cancellable;

					cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (() => {
						io_cancellable.cancel ();
						return false;
					});
					cancel_source.attach (MainContext.get_thread_default ());

					Object transport;
					var stream_request = yield perform_attach_to (pid, options, io_cancellable, out transport);

					IOStream stream = yield stream_request.wait_async (io_cancellable);

					uint controller_registration_id;
					try {
						connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
							AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
							null, io_cancellable);

						controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER,
							(AgentController) this);

						connection.start_message_processing ();

						provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
							DO_NOT_LOAD_PROPERTIES, io_cancellable);
					} catch (GLib.Error e) {
						if (e is IOError.CANCELLED)
							throw e;
						else
							throw new Error.PROCESS_NOT_RESPONDING ("%s", e.message);
					}

					entry = new AgentEntry (pid, transport, connection, provider, controller_registration_id);
				}

				connection.on_closed.connect (on_agent_connection_closed);
				provider.closed.connect (on_agent_session_provider_closed);
				provider.eternalized.connect (on_agent_session_provider_eternalized);
				entry.child_gating_changed.connect (on_child_gating_changed);

				promise.resolve (entry);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED && (cancellable == null || !cancellable.is_cancelled ())) {
					e = new Error.PROCESS_NOT_RESPONDING ("Process with pid %u either refused to load frida-agent, " +
						"or terminated during injection", pid);
				}

				agent_entries.unset (pid);

				promise.reject (e);
				throw_api_error (e);
			} finally {
				pending_establish_ops.unset (pid);
				if (cancel_source != null)
					cancel_source.destroy ();
			}

			return entry;
		}

		internal async void wait_for_uninject_of_pid (uint pid, Cancellable? cancellable) throws IOError {
			yield wait_for_uninject (injector, cancellable, () => {
				return injectee_by_pid.has_key (pid);
			});
		}

		protected virtual void on_uninjected (uint id) {
			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					uint pid = entry.key;

					injectee_by_pid.unset (pid);

					var io_cancellable = pending_establish_ops[pid];
					if (io_cancellable != null)
						io_cancellable.cancel ();

					return;
				}
			}

			uninjected (InjectorPayloadId (id));
		}

		protected abstract async Future<IOStream> perform_attach_to (uint pid, HashTable<string, Variant> options,
			Cancellable? cancellable, out Object? transport) throws Error, IOError;

		protected virtual string? get_emulated_agent_path (uint pid) throws Error {
			return null;
		}

		protected string make_agent_parameters (uint pid, string remote_address, HashTable<string, Variant> options) throws Error {
			var parameters = new StringBuilder (remote_address);

			string[] features = { "exceptor", "exit-monitor", "thread-suspend-monitor" };
			bool is_system_session = pid == 0;
			foreach (string feature in features) {
				bool enabled = true;

				if (is_system_session) {
					enabled = feature == "exceptor";
				} else {
					Variant? val = options[feature];
					if (val != null) {
						if (!val.is_of_type (VariantType.STRING) || val.get_string () != "off")
							throw new Error.INVALID_ARGUMENT ("The '%s' option is invalid", feature);
						enabled = false;
					}
				}

				if (!enabled) {
					parameters
						.append_c ('|')
						.append (feature)
						.append (":off");
				}
			}

			return parameters.str;
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry? entry = agent_sessions[id];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");

			DBusConnection connection = entry.connection;

			AgentSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.for_agent_session (id), DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			assert (entry.sink_registration_id == 0);
			try {
				entry.sink_registration_id = connection.register_object (ObjectPath.for_agent_message_sink (id), sink);
			} catch (IOError e) {
				assert_not_reached ();
			}

			return session;
		}

		public void unlink_agent_session (AgentSessionId id) {
			AgentSessionEntry? entry = agent_sessions[id];
			if (entry == null || entry.sink_registration_id == 0)
				return;

			entry.connection.unregister_object (entry.sink_registration_id);
			entry.sink_registration_id = 0;
		}

		public bool can_pass_file_descriptors_to_agent_session (AgentSessionId id) throws Error {
			AgentSessionEntry? entry = agent_sessions[id];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");

			return (entry.connection.get_capabilities () & DBusCapabilityFlags.UNIX_FD_PASSING) != 0;
		}

		public AgentSessionProvider obtain_session_provider (AgentSessionId id) throws Error {
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.sessions.contains (id))
					return entry.provider;
			}

			throw new Error.INVALID_ARGUMENT ("Invalid session ID");
		}

		private void on_agent_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = !remote_peer_vanished && error == null;
			if (closed_by_us)
				return;

			AgentEntry entry_to_remove = null;
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}
			assert (entry_to_remove != null);

			destroy.begin (entry_to_remove, entry_to_remove.disconnect_reason, io_cancellable);
		}

		private void on_agent_session_provider_closed (AgentSessionId id) {
			var closed_after_opening = agent_sessions.unset (id);
			if (!closed_after_opening)
				return;
			var reason = SessionDetachReason.APPLICATION_REQUESTED;
			agent_session_detached (id, reason, CrashInfo.empty ());

			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;

				var sessions = entry.sessions;
				if (sessions.remove (id)) {
					if (sessions.is_empty) {
						bool is_system_session = entry.pid == 0;
						if (!is_system_session && !entry.eternalized)
							unload_and_destroy.begin (entry, reason);
					}

					break;
				}
			}
		}

		private void on_agent_session_provider_eternalized (AgentSessionProvider provider) {
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.provider == provider) {
					entry.eternalized = true;
					break;
				}
			}
		}

		private void on_child_gating_changed (AgentEntry entry, uint subscriber_count) {
			var pid = entry.pid;

			if (subscriber_count == 0) {
				foreach (var child in pending_children.values.to_array ()) {
					if (child.parent_pid == pid)
						resume.begin (child.pid, null);
				}
			}

			notify_child_gating_changed (pid, subscriber_count);
		}

		private async void unload_and_destroy (AgentEntry entry, SessionDetachReason reason) throws IOError {
			if (!prepare_teardown (entry))
				return;

			try {
				yield entry.provider.unload (io_cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED) {
					entry.detach ();
					throw (IOError) e;
				}
			}

			try {
				yield teardown (entry, reason, io_cancellable);
			} catch (IOError e) {
				entry.detach ();
				throw e;
			}
		}

		private async void destroy (AgentEntry entry, SessionDetachReason reason, Cancellable? cancellable) throws IOError {
			if (!prepare_teardown (entry))
				return;

			try {
				yield teardown (entry, reason, cancellable);
			} catch (IOError e) {
				entry.detach ();
				throw e;
			}
		}

		private bool prepare_teardown (AgentEntry entry) {
			if (!agent_entries.unset (entry.pid))
				return false;

			entry.child_gating_changed.disconnect (on_child_gating_changed);
			entry.provider.closed.disconnect (on_agent_session_provider_closed);
			entry.provider.eternalized.disconnect (on_agent_session_provider_eternalized);
			entry.connection.on_closed.disconnect (on_agent_connection_closed);

			return true;
		}

		private async void teardown (AgentEntry entry, SessionDetachReason reason, Cancellable? cancellable) throws IOError {
			CrashInfo? crash = null;
			if (reason == PROCESS_TERMINATED)
				crash = yield try_collect_crash (entry.pid, cancellable);

			var crash_info = (crash != null) ? crash : CrashInfo.empty ();
			foreach (var id in entry.sessions) {
				if (agent_sessions.unset (id))
					agent_session_detached (id, reason, crash_info);
			}

			yield entry.close (cancellable);
		}

		protected virtual async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			return null;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var raw_id = yield injector.inject_library_file (pid, path, entrypoint, data, cancellable);
			return InjectorPayloadId (raw_id);
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var blob_bytes = new Bytes (blob);
			var raw_id = yield injector.inject_library_blob (pid, blob_bytes, entrypoint, data, cancellable);
			return InjectorPayloadId (raw_id);
		}

#if !WINDOWS
		public async HostChildId prepare_to_fork (uint parent_pid, Cancellable? cancellable, out uint parent_injectee_id,
				out uint child_injectee_id, out GLib.Socket child_socket) throws Error, IOError {
			if (!injectee_by_pid.has_key (parent_pid))
				throw new Error.INVALID_ARGUMENT ("No injectee found for PID %u", parent_pid);
			parent_injectee_id = injectee_by_pid[parent_pid];
			child_injectee_id = yield injector.demonitor_and_clone_state (parent_injectee_id, cancellable);

			var fds = new int[2];
			Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds);

			UnixSocket.tune_buffer_sizes (fds[0]);
			UnixSocket.tune_buffer_sizes (fds[1]);

			Socket local_socket, remote_socket;
			IOStream local_stream;
			try {
				local_socket = new Socket.from_fd (fds[0]);
				remote_socket = new Socket.from_fd (fds[1]);

				local_stream = SocketConnection.factory_create_connection (local_socket);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var id = HostChildId (next_host_child_id++);

			start_child_connection.begin (id, local_stream);

			child_socket = remote_socket;

			return id;
		}
#endif

		public async HostChildId prepare_to_specialize (uint pid, string identifier, Cancellable? cancellable,
				out uint specialized_injectee_id, out string specialized_pipe_address) throws Error, IOError {
			Future<AgentEntry>? request = agent_entries[pid];
			if (request == null || !request.ready || !injectee_by_pid.has_key (pid))
				throw new Error.INVALID_ARGUMENT ("No injectee found for PID %u", pid);

			specialized_injectee_id = injectee_by_pid[pid];

			yield injector.demonitor (specialized_injectee_id, cancellable);

			var transport = new PipeTransport ();
			var stream_request = Pipe.open (transport.local_address, cancellable);

			var id = HostChildId (next_host_child_id++);

			start_specialized_connection.begin (id, transport, stream_request);

			specialized_pipe_address = transport.remote_address;

			return id;
		}

		private async void start_specialized_connection (HostChildId id, PipeTransport transport,
				Future<IOStream> stream_request) throws GLib.Error {
			IOStream stream = yield stream_request.wait_async (io_cancellable);

			yield start_child_connection (id, stream);
		}

		private async void start_child_connection (HostChildId id, IOStream stream) throws GLib.Error {
			var connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
				null, io_cancellable);

			uint controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER, (AgentController) this);

			connection.start_message_processing ();

			var entry = new ChildEntry (connection, controller_registration_id);
			child_entries[id] = entry;
			connection.on_closed.connect (on_child_connection_closed);
		}

		private void on_child_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			ChildEntry entry_to_remove = null;
			HostChildId? child_id = null;
			foreach (var e in child_entries.entries) {
				var entry = e.value;
				if (entry.connection == connection) {
					entry_to_remove = entry;
					child_id = e.key;
					break;
				}
			}
			assert (entry_to_remove != null);

			connection.on_closed.disconnect (on_child_connection_closed);
			child_entries.unset (child_id);

			entry_to_remove.close.begin (io_cancellable);
		}

		public async void recreate_agent_thread (uint pid, uint injectee_id, Cancellable? cancellable) throws Error, IOError {
			injectee_by_pid[pid] = injectee_id;

			yield injector.recreate_thread (pid, injectee_id, cancellable);
		}

		public async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info, Cancellable? cancellable)
				throws Error, IOError {
			var child_entry = child_entries[id];
			if (child_entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			uint pid = info.pid;
			var connection = child_entry.connection;

			var promise = new Promise<AgentEntry> ();
			agent_entries[pid] = promise.future;

			AgentSessionProvider provider;
			try {
				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (GLib.Error e) {
				agent_entries.unset (pid);
				promise.reject (new Error.TRANSPORT (e.message));

				child_entry.close_soon ();

				return;
			}

			connection.on_closed.disconnect (on_child_connection_closed);
			child_entries.unset (id);

			var resume_request = new Promise<bool> ();

			var agent_entry = new AgentEntry (pid, null, connection, provider, child_entry.controller_registration_id);
			agent_entry.resume_request = resume_request;
			promise.resolve (agent_entry);

			connection.on_closed.connect (on_agent_connection_closed);
			provider.closed.connect (on_agent_session_provider_closed);
			provider.eternalized.connect (on_agent_session_provider_eternalized);
			agent_entry.child_gating_changed.connect (on_child_gating_changed);

			if (!try_handle_child (info))
				add_pending_child (info);

			yield resume_request.future.wait_async (cancellable);
		}

		public async void prepare_to_exec (HostChildInfo info, Cancellable? cancellable) throws Error, IOError {
			var pid = info.pid;

			AgentEntry? entry_to_wait_for = null;
			var entry_future = agent_entries[pid];
			if (entry_future != null) {
				try {
					var entry = yield entry_future.wait_async (cancellable);
					entry.disconnect_reason = PROCESS_REPLACED;
					entry_to_wait_for = entry;
				} catch (GLib.Error e) {
				}
			}

			yield prepare_exec_transition (pid, cancellable);

			wait_for_exec_and_deliver.begin (info, entry_to_wait_for, cancellable);
		}

		private async void wait_for_exec_and_deliver (HostChildInfo info, AgentEntry? entry_to_wait_for, Cancellable? cancellable)
				throws IOError {
			var pid = info.pid;

			try {
				yield await_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				return;
			}

			if (entry_to_wait_for != null)
				yield entry_to_wait_for.wait_until_closed (cancellable);

			add_pending_child (info);
		}

		public async void cancel_exec (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield cancel_exec_transition (pid, cancellable);

			var entry_future = agent_entries[pid];
			if (entry_future != null) {
				try {
					var entry = yield entry_future.wait_async (cancellable);
					entry.disconnect_reason = PROCESS_TERMINATED;
				} catch (GLib.Error e) {
				}
			}
		}

		public async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state, Cancellable? cancellable)
				throws Error, IOError {
			var pid = info.pid;

			var request = new SpawnAckRequest (start_state);

			pending_acks[pid] = request;

			add_pending_child (info);

			yield request.await (cancellable);
		}

		private void add_pending_child (HostChildInfo info) {
			pending_children[info.pid] = info;
			child_added (info);

			garbage_collect_pending_children_soon ();
		}

		private void garbage_collect_pending_children_soon () {
			if (pending_children_gc_timer != null || pending_children_gc_request != null)
				return;

			var timer = new TimeoutSource.seconds (1);
			timer.set_callback (() => {
				pending_children_gc_timer = null;
				garbage_collect_pending_children.begin (io_cancellable);
				return false;
			});
			timer.attach (MainContext.get_thread_default ());
			pending_children_gc_timer = timer;
		}

		private async void garbage_collect_pending_children (Cancellable? cancellable) throws IOError {
			while (pending_children_gc_request != null) {
				try {
					yield pending_children_gc_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			pending_children_gc_request = new Promise<bool> ();

			foreach (var pid in pending_children.keys.to_array ()) {
				if (!process_is_alive (pid)) {
					try {
						yield resume (pid, cancellable);
					} catch (GLib.Error e) {
					}
				}
			}

			pending_children_gc_request.resolve (true);
			pending_children_gc_request = null;

			if (!pending_children.is_empty)
				garbage_collect_pending_children_soon ();
		}

		private class AgentEntry : Object {
			public signal void child_gating_changed (uint subscriber_count);

			public uint pid {
				get;
				construct;
			}

			public Object? transport {
				get;
				construct;
			}

			public DBusConnection? connection {
				get;
				construct;
			}

			public AgentSessionProvider provider {
				get;
				construct;
			}

			public uint controller_registration_id {
				get;
				construct;
			}

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			public SessionDetachReason disconnect_reason {
				get;
				set;
				default = PROCESS_TERMINATED;
			}

			public Promise<bool>? resume_request {
				get;
				set;
			}

			public bool eternalized {
				get;
				set;
				default = false;
			}

			private bool closing = false;
			private bool registered = true;
			private Promise<bool> close_request = new Promise<bool> ();

			public AgentEntry (uint pid, Object? transport, DBusConnection? connection, AgentSessionPro
```