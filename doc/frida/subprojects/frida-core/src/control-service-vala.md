Response:
`control-service.vala` 是 Frida 动态插桩工具的核心控制服务实现文件，主要负责管理 Frida 的核心功能，包括进程注入、会话管理、调试控制等。以下是对该文件功能的详细分析：

### 1. **功能概述**
   - **控制服务管理**：`ControlService` 类负责管理 Frida 的控制服务，包括启动、停止、会话管理、进程注入等功能。
   - **进程注入与调试**：支持对目标进程的注入、调试、挂起、恢复等操作。
   - **会话管理**：管理多个 `AgentSession`，每个会话对应一个被调试的进程或应用程序。
   - **动态接口处理**：处理动态接口的连接和断开，支持多接口的并发处理。
   - **认证与授权**：通过 `AuthenticationChannel` 处理客户端的认证请求。
   - **网络通信**：通过 `WebService` 和 `DBusConnection` 处理与客户端的通信。

### 2. **涉及二进制底层与 Linux 内核的功能**
   - **进程注入**：通过 `inject_library_file` 和 `inject_library_blob` 方法，Frida 可以将动态库注入到目标进程中，实现对目标进程的调试和插桩。
     - 例如，在 Linux 上，Frida 使用 `ptrace` 系统调用来附加到目标进程，并通过 `dlopen` 加载注入的动态库。
   - **进程挂起与恢复**：通过 `resume` 和 `kill` 方法，Frida 可以控制目标进程的执行状态。
     - 在 Linux 上，`ptrace` 系统调用也用于挂起和恢复进程。
   - **进程间通信**：Frida 使用 Unix 域套接字或 TCP 套接字进行进程间通信，特别是在 `TransportBroker` 中处理 TCP 传输。

### 3. **LLDB 调试示例**
   如果你想使用 LLDB 来调试 Frida 的进程注入功能，可以使用以下 LLDB 命令或 Python 脚本来复现源代码中的调试功能。

#### LLDB 命令示例：
```bash
# 启动 LLDB 并附加到目标进程
lldb -p <target_pid>

# 设置断点，例如在注入动态库时
b frida_agent_main

# 继续执行
continue

# 查看注入的动态库
image list
```

#### LLDB Python 脚本示例：
```python
import lldb

def inject_and_debug(pid, library_path):
    # 启动 LLDB 并附加到目标进程
    debugger = lldb.SBDebugger.Create()
    target = debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)

    # 设置断点
    breakpoint = target.BreakpointCreateByName("frida_agent_main", target.GetExecutable().GetFilename())
    print(f"Breakpoint set at frida_agent_main")

    # 继续执行
    process.Continue()

    # 注入动态库
    process.LoadImage(lldb.SBFileSpec(library_path))
    print(f"Injected library: {library_path}")

    # 查看注入的动态库
    for module in target.modules:
        print(module)

# 使用示例
inject_and_debug(1234, "/path/to/frida-agent.so")
```

### 4. **假设输入与输出**
   - **输入**：用户通过 Frida 客户端发送命令，例如附加到进程、注入动态库、挂起进程等。
   - **输出**：Frida 服务端执行相应的操作，并返回结果给客户端。例如，成功附加到进程后，返回 `AgentSessionId`，客户端可以通过该 ID 进行后续的调试操作。

### 5. **常见使用错误**
   - **权限不足**：在 Linux 上，Frida 需要足够的权限才能附加到目标进程。如果权限不足，可能会导致 `ptrace` 调用失败。
     - **解决方法**：以 root 权限运行 Frida，或者配置系统的 `ptrace` 权限。
   - **目标进程崩溃**：如果注入的动态库存在问题，可能会导致目标进程崩溃。
     - **解决方法**：确保注入的动态库是经过测试的，并且在注入前备份目标进程的状态。

### 6. **用户操作步骤**
   1. **启动 Frida 服务**：用户通过命令行或脚本启动 Frida 服务。
   2. **连接客户端**：客户端通过 TCP 或 Unix 域套接字连接到 Frida 服务。
   3. **认证与授权**：客户端通过 `AuthenticationChannel` 进行认证。
   4. **附加到目标进程**：客户端发送 `attach` 命令，Frida 服务附加到目标进程并返回 `AgentSessionId`。
   5. **注入动态库**：客户端发送 `inject_library_file` 或 `inject_library_blob` 命令，Frida 服务将动态库注入到目标进程。
   6. **调试与控制**：客户端通过 `AgentSession` 进行调试和控制，例如设置断点、读取内存等。

### 7. **调试线索**
   - **进程注入失败**：如果注入失败，可以通过 LLDB 或 GDB 附加到 Frida 服务进程，查看 `inject_library_file` 或 `inject_library_blob` 的执行情况。
   - **会话管理问题**：如果会话管理出现问题，可以检查 `AgentSessionEntry` 的状态，查看会话是否被正确创建和管理。

通过以上分析，你可以更好地理解 `control-service.vala` 的功能，并在实际调试中使用 LLDB 或 GDB 来复现和调试 Frida 的核心功能。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/control-service.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```
namespace Frida {
#if HAVE_LOCAL_BACKEND
	public class ControlService : Object {
		public EndpointParameters endpoint_params {
			get;
			construct;
		}

		public ControlServiceOptions options {
			get;
			construct;
		}

		private HostSession host_session;

		private State state = STOPPED;

		private WebService service;
		private ConnectionHandler main_handler;
		private Gee.Map<string, ConnectionHandler> dynamic_interface_handlers = new Gee.HashMap<string, ConnectionHandler> ();

		private Gee.Set<ControlChannel> spawn_gaters = new Gee.HashSet<ControlChannel> ();
		private Gee.Map<uint, PendingSpawn> pending_spawn = new Gee.HashMap<uint, PendingSpawn> ();
		private Gee.Map<AgentSessionId?, AgentSessionEntry> sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Cancellable io_cancellable = new Cancellable ();

		private MainContext? main_context;

		private enum State {
			STOPPED,
			STARTING,
			STARTED,
			STOPPING
		}

		public ControlService (EndpointParameters endpoint_params, ControlServiceOptions? options = null) {
			ControlServiceOptions opts = (options != null) ? options : new ControlServiceOptions ();

			HostSession session;
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			session = new WindowsHostSession (new WindowsHelperProcess (tempdir), tempdir);
#endif
#if DARWIN
			session = new DarwinHostSession (new DarwinHelperBackend (), new TemporaryDirectory (),
				opts.sysroot, opts.report_crashes);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			session = new LinuxHostSession (new LinuxHelperProcess (tempdir), tempdir, opts.report_crashes);
#endif
#if FREEBSD
			session = new FreebsdHostSession ();
#endif
#if QNX
			session = new QnxHostSession ();
#endif

			Object (
				endpoint_params: endpoint_params,
				options: opts
			);

			assign_session (session);
		}

		internal ControlService.with_host_session (HostSession host_session, EndpointParameters endpoint_params,
				ControlServiceOptions? options = null) {
			Object (
				endpoint_params: endpoint_params,
				options: (options != null) ? options : new ControlServiceOptions ()
			);

			assign_session (host_session);
		}

		construct {
			var iface_observer = new TunnelInterfaceObserver ();
			iface_observer.interface_detached.connect (on_interface_detached);

			service = new WebService (endpoint_params, WebServiceFlavor.CONTROL, PortConflictBehavior.FAIL, iface_observer);

			main_handler = new ConnectionHandler (this, null);
		}

		private void assign_session (HostSession session) {
			host_session = session;
			host_session.spawn_added.connect (notify_spawn_added);
			host_session.child_added.connect (notify_child_added);
			host_session.child_removed.connect (notify_child_removed);
			host_session.process_crashed.connect (notify_process_crashed);
			host_session.output.connect (notify_output);
			host_session.agent_session_detached.connect (on_agent_session_detached);
			host_session.uninjected.connect (notify_uninjected);
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STOPPED)
				throw new Error.INVALID_OPERATION ("Invalid operation");
			state = STARTING;

			main_context = MainContext.ref_thread_default ();

			service.incoming.connect (on_server_connection);

			try {
				yield service.start (cancellable);

				if (options.enable_preload) {
					var base_host_session = host_session as BaseDBusHostSession;
					if (base_host_session != null)
						base_host_session.preload.begin (io_cancellable);
				}

				state = STARTED;
			} finally {
				if (state != STARTED)
					state = STOPPED;
			}
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STARTED)
				throw new Error.INVALID_OPERATION ("Invalid operation");
			state = STOPPING;

			service.incoming.disconnect (on_server_connection);

			io_cancellable.cancel ();

			service.stop ();

			foreach (var handler in dynamic_interface_handlers.values.to_array ())
				yield handler.close (cancellable);
			dynamic_interface_handlers.clear ();

			yield main_handler.close (cancellable);

			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session != null)
				yield base_host_session.close (cancellable);

			state = STOPPED;
		}

		public void stop_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StopTask> ().execute (cancellable);
		}

		private class StopTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.stop (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ControlServiceTask<T> : AsyncTask<T> {
			public weak ControlService parent {
				get;
				construct;
			}
		}

		private void on_server_connection (IOStream connection, SocketAddress remote_address, DynamicInterface? dynamic_iface) {
#if IOS || TVOS
			/*
			 * We defer the launchd injection until the first connection is established in order
			 * to avoid bootloops on unsupported jailbreaks.
			 */
			var darwin_host_session = host_session as DarwinHostSession;
			if (darwin_host_session != null)
				darwin_host_session.activate_crash_reporter_integration ();
#endif

			ConnectionHandler handler;
			unowned string iface_name = dynamic_iface?.name;
			if (iface_name != null) {
				handler = dynamic_interface_handlers[iface_name];
				if (handler == null) {
					handler = new ConnectionHandler (this, dynamic_iface);
					dynamic_interface_handlers[iface_name] = handler;
				}
			} else {
				handler = main_handler;
			}

			handler.handle_server_connection.begin (connection);
		}

		private void on_interface_detached (DynamicInterface iface) {
			schedule_on_frida_thread (() => {
				ConnectionHandler handler;
				if (dynamic_interface_handlers.unset (iface.name, out handler))
					handler.close.begin (io_cancellable);
				return Source.REMOVE;
			});
		}

		private async void teardown_control_channel (ControlChannel channel) {
			foreach (AgentSessionId id in channel.sessions) {
				AgentSessionEntry entry = sessions[id];

				var base_host_session = host_session as BaseDBusHostSession;
				if (base_host_session != null)
					base_host_session.unlink_agent_session (id);

				AgentSession? session = entry.session;

				if (entry.persist_timeout == 0 || session == null) {
					sessions.unset (id);
					if (session != null)
						session.close.begin (io_cancellable);
				} else {
					entry.detach_controller ();
					session.interrupt.begin (io_cancellable);
				}
			}

			try {
				yield disable_spawn_gating (channel);
			} catch (GLib.Error e) {
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			assert (main_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class ConnectionHandler : Object {
			public weak ControlService parent {
				get;
				construct;
			}

			public DynamicInterface? dynamic_iface {
				get;
				construct;
			}

			public HostSession host_session {
				get {
					return parent.host_session;
				}
			}

			private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

			private SocketService broker_service = new SocketService ();
#if !WINDOWS
			private uint16 broker_port = 0;
#endif
			private Gee.Map<string, Transport> transports = new Gee.HashMap<string, Transport> ();

			private Cancellable io_cancellable = new Cancellable ();

			public ConnectionHandler (ControlService parent, DynamicInterface? dynamic_iface) {
				Object (parent: parent, dynamic_iface: dynamic_iface);
			}

			construct {
				broker_service.incoming.connect (on_broker_service_connection);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				broker_service.incoming.disconnect (on_broker_service_connection);

				io_cancellable.cancel ();

				broker_service.stop ();

				transports.clear ();

				foreach (var peer in peers.values.to_array ())
					yield peer.close (cancellable);
				peers.clear ();
			}

			public Gee.Iterator<ControlChannel> all_control_channels () {
				return (Gee.Iterator<ControlChannel>) peers.values.filter (peer => peer is ControlChannel);
			}

			public async void handle_server_connection (IOStream raw_connection) throws GLib.Error {
				var connection = yield new DBusConnection (raw_connection, null, DELAY_MESSAGE_PROCESSING, null,
					io_cancellable);
				connection.on_closed.connect (on_connection_closed);

				AuthenticationService? auth_service = parent.endpoint_params.auth_service;
				peers[connection] = (auth_service != null)
					? (Peer) new AuthenticationChannel (this, connection, auth_service)
					: (Peer) new ControlChannel (this, connection);

				connection.start_message_processing ();
			}

			private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
				Peer peer;
				if (peers.unset (connection, out peer))
					peer.close.begin (io_cancellable);
			}

			public async void promote_authentication_channel (AuthenticationChannel channel) throws GLib.Error {
				DBusConnection connection = channel.connection;

				peers.unset (connection);
				yield channel.close (io_cancellable);

				peers[connection] = new ControlChannel (this, connection);
			}

			public void kick_authentication_channel (AuthenticationChannel channel) {
				var source = new IdleSource ();
				source.set_callback (() => {
					channel.connection.close.begin (io_cancellable);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public async void teardown_control_channel (ControlChannel channel) {
				yield parent.teardown_control_channel (channel);
			}

			public async void enable_spawn_gating (ControlChannel requester) throws GLib.Error {
				yield parent.enable_spawn_gating (requester);
			}

			public async void disable_spawn_gating (ControlChannel requester) throws GLib.Error {
				yield parent.disable_spawn_gating (requester);
			}

			public HostSpawnInfo[] enumerate_pending_spawn () {
				return parent.enumerate_pending_spawn ();
			}

			public async void resume (uint pid, ControlChannel requester) throws GLib.Error {
				yield parent.resume (pid, requester);
			}

			public async AgentSessionId attach (uint pid, HashTable<string, Variant> options, ControlChannel requester,
					Cancellable? cancellable) throws Error, IOError {
				return yield parent.attach (pid, options, requester, cancellable);
			}

			public async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable)
					throws Error, IOError {
				yield parent.reattach (id, requester, cancellable);
			}

			public void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port, out string token)
					throws Error {
#if WINDOWS
				throw new Error.NOT_SUPPORTED ("Not yet supported on Windows");
#else
				var base_host_session = host_session as BaseDBusHostSession;
				if (base_host_session == null)
					throw new Error.NOT_SUPPORTED ("Not supported for remote host sessions");
				if (!base_host_session.can_pass_file_descriptors_to_agent_session (id))
					throw new Error.INVALID_ARGUMENT ("Not supported by this particular agent session");

				if (broker_port == 0) {
					try {
						if (dynamic_iface != null) {
							SocketAddress effective_address;
							broker_service.add_address (
								new InetSocketAddress (dynamic_iface.ip, 0),
								STREAM,
								TCP,
								null,
								out effective_address);
							broker_port = ((InetSocketAddress) effective_address).get_port ();
						} else {
							broker_port = broker_service.add_any_inet_port (null);
						}
					} catch (GLib.Error e) {
						throw new Error.NOT_SUPPORTED ("Unable to listen: %s", e.message);
					}

					broker_service.start ();
				}

				string transport_id = Uuid.string_random ();

				var expiry_source = new TimeoutSource.seconds (20);
				expiry_source.set_callback (() => {
					transports.unset (transport_id);
					return false;
				});
				expiry_source.attach (MainContext.get_thread_default ());

				transports[transport_id] = new Transport (id, expiry_source);

				port = broker_port;
				token = transport_id;
#endif
			}

			private bool on_broker_service_connection (SocketConnection connection, Object? source_object) {
				handle_broker_connection.begin (connection);
				return true;
			}

			private async void handle_broker_connection (SocketConnection connection) throws GLib.Error {
				var socket = connection.socket;
				if (socket.get_family () != UNIX)
					Tcp.enable_nodelay (socket);

				const size_t uuid_length = 36;

				var raw_token = new uint8[uuid_length + 1];
				size_t bytes_read;
				yield connection.input_stream.read_all_async (raw_token[0:uuid_length], Priority.DEFAULT, io_cancellable,
					out bytes_read);
				unowned string token = (string) raw_token;

				Transport transport;
				if (!transports.unset (token, out transport))
					return;

				transport.expiry_source.destroy ();

#if !WINDOWS
				AgentSessionId session_id = transport.session_id;

				var base_host_session = host_session as BaseDBusHostSession;
				if (base_host_session == null)
					throw new Error.NOT_SUPPORTED ("Not supported for remote host sessions");

				AgentSessionProvider provider = base_host_session.obtain_session_provider (session_id);
				yield provider.migrate (session_id, socket, io_cancellable);
#endif
			}

			private class Transport {
				public AgentSessionId session_id;
				public Source expiry_source;

				public Transport (AgentSessionId session_id, Source expiry_source) {
					this.session_id = session_id;
					this.expiry_source = expiry_source;
				}
			}
		}

		private Gee.Iterator<ControlChannel> all_control_channels () {
			var channels = new Gee.ArrayList<ControlChannel> ();
			channels.add_all_iterator (main_handler.all_control_channels ());
			foreach (var handler in dynamic_interface_handlers.values)
				channels.add_all_iterator (handler.all_control_channels ());
			return channels.iterator ();
		}

		private async void enable_spawn_gating (ControlChannel requester) throws GLib.Error {
			bool is_first = spawn_gaters.is_empty;
			spawn_gaters.add (requester);
			foreach (var spawn in pending_spawn.values)
				spawn.pending_approvers.add (requester);

			if (is_first)
				yield host_session.enable_spawn_gating (io_cancellable);
		}

		private async void disable_spawn_gating (ControlChannel requester) throws GLib.Error {
			if (spawn_gaters.remove (requester)) {
				foreach (uint pid in pending_spawn.keys.to_array ())
					host_session.resume.begin (pid, io_cancellable);
			}

			if (spawn_gaters.is_empty)
				yield host_session.disable_spawn_gating (io_cancellable);
		}

		private HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var i = 0;
			foreach (var spawn in pending_spawn.values)
				result[i++] = spawn.info;
			return result;
		}

		private async void resume (uint pid, ControlChannel requester) throws GLib.Error {
			PendingSpawn? spawn = pending_spawn[pid];
			if (spawn == null) {
				yield host_session.resume (pid, io_cancellable);
				return;
			}

			var approvers = spawn.pending_approvers;
			approvers.remove (requester);
			if (approvers.is_empty) {
				pending_spawn.unset (pid);

				yield host_session.resume (pid, io_cancellable);

				notify_spawn_removed (spawn.info);
			}
		}

		private async AgentSessionId attach (uint pid, HashTable<string, Variant> options, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId id;
			try {
				id = yield host_session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			requester.sessions.add (id);

			var opts = SessionOptions._deserialize (options);

			var entry = new AgentSessionEntry (requester, id, opts.persist_timeout, io_cancellable);
			sessions[id] = entry;
			entry.expired.connect (on_agent_session_expired);

			yield link_session (id, entry, requester, cancellable);

			return id;
		}

		private async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry? entry = sessions[id];
			if (entry == null || entry.controller != null)
				throw new Error.INVALID_OPERATION ("Invalid session ID");

			requester.sessions.add (id);

			entry.attach_controller (requester);

			yield link_session (id, entry, requester, cancellable);
		}

		private async void link_session (AgentSessionId id, AgentSessionEntry entry, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			DBusConnection controller_connection = requester.connection;

			AgentMessageSink sink;
			try {
				sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
					DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			AgentSession session;
			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session != null) {
				session = yield base_host_session.link_agent_session (id, sink, cancellable);
			} else {
				DBusConnection internal_connection = ((DBusProxy) host_session).g_connection;

				try {
					session = yield internal_connection.get_proxy (null, ObjectPath.for_agent_session (id),
						DO_NOT_LOAD_PROPERTIES, cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}

				entry.internal_connection = internal_connection;
				try {
					entry.take_internal_registration (
						internal_connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			entry.session = session;
			try {
				entry.take_controller_registration (
					controller_connection.register_object (ObjectPath.for_agent_session (id), session));
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		private void notify_spawn_added (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_added (info);
		}

		private void notify_spawn_removed (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_removed (info);
		}

		private void notify_child_added (HostChildInfo info) {
			all_control_channels ().foreach (channel => {
				channel.child_added (info);
				return true;
			});
		}

		private void notify_child_removed (HostChildInfo info) {
			all_control_channels ().foreach (channel => {
				channel.child_removed (info);
				return true;
			});
		}

		private void notify_process_crashed (CrashInfo crash) {
			all_control_channels ().foreach (channel => {
				channel.process_crashed (crash);
				return true;
			});
		}

		private void notify_output (uint pid, int fd, uint8[] data) {
			all_control_channels ().foreach (channel => {
				channel.output (pid, fd, data);
				return true;
			});
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			AgentSessionEntry entry;
			if (sessions.unset (id, out entry)) {
				ControlChannel? controller = entry.controller;
				if (controller != null) {
					controller.sessions.remove (id);
					controller.agent_session_detached (id, reason, crash);
				}
			}
		}

		private void notify_uninjected (InjectorPayloadId id) {
			all_control_channels ().foreach (channel => {
				channel.uninjected (id);
				return true;
			});
		}

		private void on_agent_session_expired (AgentSessionEntry entry) {
			sessions.unset (entry.id);
		}

		private interface Peer : Object {
			public abstract async void close (Cancellable? cancellable = null) throws IOError;
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak ConnectionHandler parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public AuthenticationService service {
				get;
				construct;
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();

			public AuthenticationChannel (ConnectionHandler parent, DBusConnection connection, AuthenticationService service) {
				Object (
					parent: parent,
					connection: connection,
					service: service
				);
			}

			construct {
				try {
					registrations.add (connection.register_object (ObjectPath.AUTHENTICATION_SERVICE,
						(AuthenticationService) this));

					HostSession host_session = new UnauthorizedHostSession ();
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, host_session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public async void close (Cancellable? cancellable) throws IOError {
				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async string authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				try {
					string session_info = yield service.authenticate (token, cancellable);
					yield parent.promote_authentication_channel (this);
					return session_info;
				} catch (GLib.Error e) {
					if (e is Error.INVALID_ARGUMENT)
						parent.kick_authentication_channel (this);
					throw e;
				}
			}
		}

		private class ControlChannel : Object, Peer, HostSession, TransportBroker {
			public weak ConnectionHandler parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();
			private TimeoutSource? ping_timer;

			public ControlChannel (ConnectionHandler parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					HostSession session = this;
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, session));

					AuthenticationService null_auth = new NullAuthenticationService ();
					registrations.add (connection.register_object (Frida.ObjectPath.AUTHENTICATION_SERVICE, null_auth));

					TransportBroker broker = this;
					registrations.add (connection.register_object (Frida.ObjectPath.TRANSPORT_BROKER, broker));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public async void close (Cancellable? cancellable) throws IOError {
				discard_ping_timer ();

				yield parent.teardown_control_channel (this);

				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
				discard_ping_timer ();

				if (interval_seconds != 0) {
					ping_timer = new TimeoutSource (interval_seconds * 1500);
					ping_timer.set_callback (on_ping_timeout);
					ping_timer.attach (MainContext.get_thread_default ());
				}
			}

			private void discard_ping_timer () {
				if (ping_timer == null)
					return;
				ping_timer.destroy ();
				ping_timer = null;
			}

			private bool on_ping_timeout () {
				connection.close.begin ();
				return false;
			}

			public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.query_system_parameters (cancellable);
			}

			public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.get_frontmost_application (options, cancellable);
			}

			public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_applications (options, cancellable);
			}

			public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_processes (options, cancellable);
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws GLib.Error {
				yield parent.enable_spawn_gating (this);
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws GLib.Error {
				yield parent.disable_spawn_gating (this);
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws GLib.Error {
				return parent.enumerate_pending_spawn ();
			}

			public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_pending_children (cancellable);
			}

			public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.spawn (program, options, cancellable);
			}

			public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws GLib.Error {
				yield parent.host_session.input (pid, data, cancellable);
			}

			public async void resume (uint pid, Cancellable? cancellable) throws GLib.Error {
				yield parent.resume (pid, this);
			}

			public async void kill (uint pid, Cancellable? cancellable) throws GLib.Error {
				yield parent.host_session.kill (pid, cancellable);
			}

			public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.attach (pid, options, this, cancellable);
			}

			public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
				yield parent.reattach (id, this, cancellable);
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.inject_library_file (pid, path, entrypoint, data, cancellable);
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}

			private async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
					out string token) throws Error {
				parent.open_tcp_transport (id, cancellable, out port, out token);
			}
		}

		private class PendingSpawn {
			public HostSpawnInfo info {
				get;
				private set;
			}

			public Gee.Set<ControlChannel> pending_approvers {
				get;
				default = new Gee.HashSet<ControlChannel> ();
			}

			public PendingSpawn (uint pid, string identifier, Gee.Iterator<ControlChannel> gaters) {
				info = HostSpawnInfo (pid, identifier);
				pending_approvers.add_all_iterator (gaters);
			}
		}

		private class AgentSessionEntry {
			public signal void expired ();

			public ControlChannel? controller {
				get;
				private set;
			}

			public AgentSessionId id {
				get;
				private set;
			}

			public AgentSession? session {
				get;
				set;
			}

			public uint persist_timeout {
				get;
				private set;
			}

			public DBusConnection? internal_connection {
				get;
				set;
			}

			public Cancellable io_cancellable {
				get;
				private set;
			}

			private Gee.Collection<uint> internal_registrations = new Gee.ArrayList<uint> ();
			private Gee.Collection<uint> controller_registrations = new Gee.ArrayList<uint> ();

			private TimeoutSource? expiry_timer;

			public AgentSessionEntry (ControlChannel controller, AgentSessionId id, uint persist_timeout,
					Cancellable io_cancellable) {
				this.controller = controller;
				this.id = id;
				this.persist_timeout = persist_timeout;
				this.io_cancellable = io_cancellable;
			}

			~AgentSessionEntry () {
				stop_expiry_timer ();
				unregister_all ();
			}

			public void detach_controller () {
				unregister_all ();
				controller = null;
				session = null;

				start_expiry_timer ();
			}

			public void attach_controller (ControlChannel c) {
				stop_expiry_timer ();

				assert (controller == null);
				controller = c;
			}

			public void take_internal_registration (uint id) {
				internal_registrations.add (id);
			}

			public void take_controller_registration (uint id) {
				controller_registrations.add (id);
			}

			private void unregister_all () {
				if (controller != null)
					unregister_all_in (controller_registrations, controller.connection);
				if (internal_connection != null)
					unregister_all_in (internal_registrations, internal_connection);
			}

			private void unregister_all_in (Gee.Collection<uint> ids, DBusConnection connection) {
				foreach (uint id in ids)
					connection.unregister_object (id);
				ids.clear ();
			}

			private void start_expiry_timer () {
				if (expiry_timer != null)
					return;
				expiry_timer = new TimeoutSource.seconds (persist_timeout + 1);
				expiry_timer.set_callback (() => {
					expired ();
					return false;
				});
				expiry_timer.attach (MainContext.get_thread_default ());
			}

			private void stop_expiry_timer () {
				if (expiry_timer == null)
					return;
				expiry_timer.destroy ();
				expiry_timer = null;
			}
		}
	}
#else
	public class ControlService : Object {
		public ControlService (EndpointParameters endpoint_params, ControlServiceOptions? options = null) {
		}

		public ControlService.with_host_session (HostSession host_session, EndpointParameters endpoint_params,
				ControlServiceOptions? options = null) {
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Local backend not available");
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
		}

		public void stop_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StopTask> ().execute (cancellable);
		}

		private class StopTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.stop (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ControlServiceTask<T> : AsyncTask<T> {
			public weak ControlService parent {
				get;
				construct;
			}
		}
	}
#endif

	public class ControlServiceOptions : Object {
		public string? sysroot {
			get;
			set;
		}

		public bool enable_preload {
			get;
			set;
			default = true;
		}

		public bool report_crashes {
			get;
			set;
			default = true;
		}
	}
}
```