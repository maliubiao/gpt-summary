Response:
### 功能归纳

`frida.vala` 文件是 Frida 动态插桩工具的核心部分，主要负责管理会话、脚本、调试器、以及与目标进程的通信。以下是该文件的主要功能：

1. **会话管理**：
   - 管理会话的生命周期，包括创建、销毁、中断和恢复会话。
   - 处理会话的迁移（如从旧会话迁移到新会话）。
   - 管理会话的持久化（persist_timeout）。

2. **脚本管理**：
   - 管理脚本的加载、卸载、永恒化（eternalize）和销毁。
   - 处理脚本的消息传递，包括从脚本发送消息到 Frida 核心，以及从 Frida 核心发送消息到脚本。
   - 支持脚本的调试器功能，包括启用和禁用调试器。

3. **调试器支持**：
   - 提供调试器的前端和后端通信功能。
   - 支持调试器的消息传递，允许前端和后端通过 WebSocket 进行通信。

4. **对等连接（Peer Connection）**：
   - 使用 ICE（Interactive Connectivity Establishment）协议建立对等连接。
   - 处理 ICE 候选者（candidates）的收集和交换。
   - 使用 DTLS（Datagram Transport Layer Security）进行安全通信。

5. **消息传递**：
   - 管理消息的批量发送和接收。
   - 处理消息的序列化和反序列化。
   - 支持消息的异步传递和重试机制。

6. **垃圾回收**：
   - 管理内存的垃圾回收，确保资源的及时释放。

### 二进制底层与 Linux 内核相关功能

1. **ICE 协议**：
   - 使用 `Nice.Agent` 来处理 ICE 协议的实现，包括候选者的收集和交换。
   - 通过 `Nice.Agent` 设置本地和远程的 ICE 凭证（ufrag 和 pwd）。

2. **DTLS 加密**：
   - 使用 `DtlsConnection` 进行 DTLS 握手，确保通信的安全性。
   - 处理证书的生成和验证，确保通信的双方是可信的。

3. **SCTP 协议**：
   - 使用 `SctpConnection` 进行消息的可靠传输，支持大消息的分片和重组。

### LLDB 调试示例

假设我们想要调试 `do_setup_peer_connection` 函数，可以使用以下 LLDB 命令或 Python 脚本来设置断点并观察函数的执行：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 设置断点
b frida::Session::do_setup_peer_connection

# 运行程序
run

# 当断点命中时，打印相关变量
p agent
p stream_id
p component_id
```

#### LLDB Python 脚本示例

```python
import lldb

def setup_peer_connection_breakpoint(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 设置断点
    breakpoint = target.BreakpointCreateByName("frida::Session::do_setup_connection")
    print(f"Breakpoint created at {breakpoint.GetLocationAtIndex(0).GetAddress()}")

    # 继续执行
    process.Continue()

    # 当断点命中时，打印相关变量
    agent = frame.FindVariable("agent")
    stream_id = frame.FindVariable("stream_id")
    component_id = frame.FindVariable("component_id")
    print(f"agent: {agent}, stream_id: {stream_id}, component_id: {component_id}")

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f setup_peer_connection_breakpoint.setup_peer_connection_breakpoint setup_peer_connection_breakpoint')
```

### 假设输入与输出

假设我们调用 `setup_peer_connection` 函数，输入为 `PeerOptions` 对象，输出为一个成功建立的对等连接。

- **输入**：
  - `PeerOptions` 对象，包含 ICE 配置、证书等信息。

- **输出**：
  - 成功建立的对等连接，返回一个 `IOStream` 对象，用于后续的通信。

### 用户常见错误

1. **会话中断**：
   - 用户在会话中断后尝试发送消息，导致 `Error.INVALID_OPERATION` 错误。
   - **解决方法**：在发送消息前检查会话状态，确保会话处于 `ATTACHED` 状态。

2. **调试器端口冲突**：
   - 用户尝试启用调试器时，指定的端口已被占用，导致 `Error.ADDRESS_IN_USE` 错误。
   - **解决方法**：选择一个未被占用的端口，或让系统自动分配端口。

3. **证书验证失败**：
   - 在对等连接建立过程中，证书验证失败，导致连接中断。
   - **解决方法**：确保双方使用相同的证书，或检查证书的生成和验证逻辑。

### 用户操作步骤与调试线索

1. **用户操作**：
   - 用户调用 `setup_peer_connection` 函数，尝试建立对等连接。
   - 用户启用调试器，指定端口并发送调试消息。

2. **调试线索**：
   - 如果连接失败，检查 `do_setup_peer_connection` 函数中的 ICE 候选者收集和交换过程。
   - 如果调试器无法启动，检查 `enable_debugger` 函数中的端口绑定和调试器初始化逻辑。
   - 如果消息传递失败，检查 `post_messages` 函数中的消息序列化和异步传递逻辑。

### 总结

`frida.vala` 文件是 Frida 工具的核心部分，负责管理会话、脚本、调试器和对等连接。它涉及底层的 ICE、DTLS 和 SCTP 协议，确保通信的安全性和可靠性。通过 LLDB 调试工具，开发者可以深入分析这些功能的执行过程，排查潜在的错误和问题。
Prompt: 
```
这是目录为frida/subprojects/frida-core/src/frida.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共3部分，请归纳一下它的功能

"""
nt.snapshot_script (embed_script, options, cancellable);
			}
		}

		public async void setup_peer_connection (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield do_setup_peer_connection (options, cancellable);
		}

#if HAVE_NICE
		private async void do_setup_peer_connection (PeerOptions? options, Cancellable? cancellable) throws Error, IOError {
			AgentSession server_session = active_session;

			frida_context = get_main_context ();
			dbus_context = yield get_dbus_context ();

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, ICE_TRICKLE);
			agent.set_software ("Frida");
			agent.controlling_mode = true;
			agent.ice_tcp = false;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");

			yield PeerConnection.configure_agent (agent, stream_id, component_id, options, cancellable);

			uint8[] cert_der;
			string cert_pem, key_pem;
			yield generate_certificate (out cert_der, out cert_pem, out key_pem);

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem + key_pem, -1);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var offer = new PeerSessionDescription ();
			offer.session_id = PeerSessionId.generate ();
			agent.get_local_credentials (stream_id, out offer.ice_ufrag, out offer.ice_pwd);
			offer.ice_trickle = true;
			offer.fingerprint = PeerConnection.compute_certificate_fingerprint (cert_der);
			offer.setup = ACTPASS;

			string offer_sdp = offer.to_sdp ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			IOStream stream = null;
			server_session.new_candidates.connect (on_new_candidates);
			server_session.candidate_gathering_done.connect (on_candidate_gathering_done);
			try {
				string answer_sdp;
				try {
					yield server_session.offer_peer_connection (offer_sdp, raw_options, cancellable, out answer_sdp);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var answer = PeerSessionDescription.parse (answer_sdp);
				agent.set_remote_credentials (stream_id, answer.ice_ufrag, answer.ice_pwd);

				if (nice_agent != null)
					throw new Error.INVALID_OPERATION ("Peer connection already exists");

				nice_agent = agent;
				nice_cancellable = new Cancellable ();
				nice_stream_id = stream_id;
				nice_component_id = component_id;

				var open_request = new Promise<IOStream> ();

				schedule_on_dbus_thread (() => {
					open_peer_connection.begin (server_session, certificate, answer, open_request);
					return false;
				});

				stream = yield open_request.future.wait_async (cancellable);
			} finally {
				server_session.candidate_gathering_done.disconnect (on_candidate_gathering_done);
				server_session.new_candidates.disconnect (on_new_candidates);
			}

			try {
				nice_connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING, null, nice_cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
			nice_connection.on_closed.connect (on_nice_connection_closed);

			try {
				nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_MESSAGE_SINK,
					(AgentMessageSink) this);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			nice_connection.start_message_processing ();

			AgentSession peer_session;
			try {
				peer_session = yield nice_connection.get_proxy (null, ObjectPath.AGENT_SESSION, DO_NOT_LOAD_PROPERTIES,
					nice_cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			try {
				yield server_session.begin_migration (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			begin_migration (peer_session);

			try {
				yield server_session.commit_migration (cancellable);
			} catch (GLib.Error e) {
				cancel_migration (peer_session);
				throw_dbus_error (e);
			}

			nice_options = (options != null) ? options : new PeerOptions ();
		}

		private async void teardown_peer_connection (Cancellable? cancellable) throws IOError {
			Nice.Agent? agent = nice_agent;
			DBusConnection? conn = nice_connection;

			discard_peer_connection ();

			if (conn != null) {
				try {
					yield conn.close (cancellable);
				} catch (GLib.Error e) {
				}
			}

			if (agent != null) {
				schedule_on_dbus_thread (() => {
					agent.close_async.begin ();

					schedule_on_frida_thread (() => {
						teardown_peer_connection.callback ();
						return false;
					});

					return false;
				});
				yield;
			}
		}

		private void discard_peer_connection () {
			nice_cancellable = null;

			if (nice_registration_id != 0) {
				nice_connection.unregister_object (nice_registration_id);
				nice_registration_id = 0;
			}

			if (nice_connection != null) {
				nice_connection.on_closed.disconnect (on_nice_connection_closed);
				nice_connection = null;
			}

			nice_iostream = null;

			nice_component_id = 0;
			nice_stream_id = 0;

			nice_agent = null;
		}

		private async void open_peer_connection (AgentSession server_session, TlsCertificate certificate,
				PeerSessionDescription answer, Promise<IOStream> promise) {
			Nice.Agent agent = nice_agent;
			DtlsConnection? tc = null;
			ulong candidate_handler = 0;
			ulong gathering_handler = 0;
			ulong accept_handler = 0;
			try {
				agent.component_state_changed.connect (on_component_state_changed);

				var pending_candidates = new Gee.ArrayList<string> ();
				candidate_handler = agent.new_candidate_full.connect (candidate => {
					string candidate_sdp = agent.generate_local_candidate_sdp (candidate);
					pending_candidates.add (candidate_sdp);
					if (pending_candidates.size == 1) {
						schedule_on_dbus_thread (() => {
							var stolen_candidates = pending_candidates;
							pending_candidates = new Gee.ArrayList<string> ();

							schedule_on_frida_thread (() => {
								if (nice_agent == null)
									return false;

								server_session.add_candidates.begin (stolen_candidates.to_array (),
									nice_cancellable);

								return false;
							});

							return false;
						});
					}
				});

				gathering_handler = agent.candidate_gathering_done.connect (stream_id => {
					schedule_on_dbus_thread (() => {
						schedule_on_frida_thread (() => {
							if (nice_agent == null)
								return false;
							server_session.notify_candidate_gathering_done.begin (nice_cancellable);
							return false;
						});
						return false;
					});
				});

				if (!agent.gather_candidates (nice_stream_id))
					throw new Error.NOT_SUPPORTED ("Unable to gather local candidates");

				var socket = new PeerSocket (agent, nice_stream_id, nice_component_id);

				if (answer.setup == ACTIVE) {
					var dsc = DtlsServerConnection.new (socket, certificate);
					dsc.authentication_mode = REQUIRED;
					tc = dsc;
				} else {
					tc = DtlsClientConnection.new (socket, null);
					tc.set_certificate (certificate);
				}
				tc.set_database (null);
				accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return PeerConnection.compute_certificate_fingerprint (peer_cert.certificate.data) == answer.fingerprint;
				});
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);

				nice_iostream = new SctpConnection (tc, answer.setup, answer.sctp_port, answer.max_message_size);

				schedule_on_frida_thread (() => {
					promise.resolve (nice_iostream);
					return false;
				});
			} catch (GLib.Error e) {
				string message = (e is IOError.CANCELLED)
					? "Unable to establish peer connection"
					: e.message;
				Error error = new Error.TRANSPORT ("%s", message);
				schedule_on_frida_thread (() => {
					nice_component_id = 0;
					nice_stream_id = 0;
					nice_cancellable = null;
					nice_agent = null;

					promise.reject (error);
					return false;
				});
			} finally {
				if (accept_handler != 0)
					tc.disconnect (accept_handler);
				if (gathering_handler != 0)
					agent.disconnect (gathering_handler);
				if (candidate_handler != 0)
					agent.disconnect (candidate_handler);
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			if (state == FAILED)
				nice_cancellable.cancel ();
		}

		private void on_new_candidates (string[] candidate_sdps) {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				return;

			string[] candidate_sdps_copy = candidate_sdps;
			schedule_on_dbus_thread (() => {
				var candidates = new SList<Nice.Candidate> ();
				foreach (unowned string sdp in candidate_sdps_copy) {
					var candidate = agent.parse_remote_candidate_sdp (nice_stream_id, sdp);
					if (candidate != null)
						candidates.append (candidate);
				}

				agent.set_remote_candidates (nice_stream_id, nice_component_id, candidates);

				return false;
			});
		}

		private void on_candidate_gathering_done () {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				return;

			schedule_on_dbus_thread (() => {
				agent.peer_candidate_gathering_done (nice_stream_id);

				return false;
			});
		}

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			handle_nice_connection_closure.begin ();
		}

		private async void handle_nice_connection_closure () {
			try {
				yield teardown_peer_connection (null);
			} catch (IOError e) {
				assert_not_reached ();
			}

			if (persist_timeout != 0) {
				if (state != ATTACHED)
					return;
				state = INTERRUPTED;
				active_session = obsolete_session;
				obsolete_session = null;
				delivery_cancellable.cancel ();
				detached (CONNECTION_TERMINATED, null);
			} else {
				_do_close.begin (CONNECTION_TERMINATED, CrashInfo.empty (), false, null);
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			assert (dbus_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}
#else
		private async void do_setup_peer_connection (PeerOptions? options, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection (Cancellable? cancellable) throws IOError {
		}

		private void discard_peer_connection () {
		}
#endif

		public void setup_peer_connection_sync (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<SetupPeerConnectionTask> ();
			task.options = options;
			task.execute (cancellable);
		}

		private class SetupPeerConnectionTask : SessionTask<void> {
			public PeerOptions? options;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.setup_peer_connection (options, cancellable);
			}
		}

		public async PortalMembership join_portal (string address, PortalOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			PortalMembershipId membership_id;
			try {
				membership_id = yield active_session.join_portal (address, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new PortalMembership (this, membership_id);
		}

		public PortalMembership join_portal_sync (string address, PortalOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<JoinPortalTask> ();
			task.address = address;
			task.options = options;
			return task.execute (cancellable);
		}

		private class JoinPortalTask : SessionTask<PortalMembership> {
			public string address;
			public PortalOptions? options;

			protected override async PortalMembership perform_operation () throws Error, IOError {
				return yield parent.join_portal (address, options, cancellable);
			}
		}

		protected async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");

			foreach (var m in messages) {
				switch (m.kind) {
					case SCRIPT: {
						var script = scripts[m.script_id];
						if (script != null)
							script.message (m.text, m.has_data ? new Bytes (m.data) : null);
						break;
					}
					case DEBUGGER:
						var script = scripts[m.script_id];
						if (script != null)
							script.on_debugger_message_from_backend (m.text);
						break;
				}
			}

			last_rx_batch_id = batch_id;
		}

		internal void _post_to_agent (AgentMessageKind kind, AgentScriptId script_id, string text, Bytes? data = null) {
			if (state == DETACHED)
				return;
			pending_messages.offer (new PendingMessage (next_serial++, kind, script_id, text, data));
			maybe_deliver_pending_messages ();
		}

		private void maybe_deliver_pending_messages () {
			if (state != ATTACHED)
				return;

			AgentSession sink = active_session;

			if (pending_messages.is_empty)
				return;

			var batch = new Gee.ArrayList<PendingMessage> ();
			void * items = null;
			int n_items = 0;
			size_t total_size = 0;
			size_t max_size = 4 * 1024 * 1024;
			PendingMessage? m;
			while ((m = pending_messages.peek ()) != null) {
				size_t message_size = m.estimate_size_in_bytes ();
				if (total_size + message_size > max_size && !batch.is_empty)
					break;
				pending_messages.poll ();
				batch.add (m);

				n_items++;
				items = realloc (items, n_items * sizeof (AgentMessage));

				AgentMessage * am = (AgentMessage *) items + n_items - 1;

				am->kind = m.kind;
				am->script_id = m.script_id;

				*((void **) &am->text) = m.text;

				unowned Bytes? data = m.data;
				am->has_data = data != null;
				*((void **) &am->data) = am->has_data ? data.get_data () : null;
				am->data.length = am->has_data ? data.length : 0;

				total_size += message_size;
			}

			if (persist_timeout == 0)
				emit_batch (sink, batch, items);
			else
				deliver_batch.begin (sink, batch, items);
		}

		private void emit_batch (AgentSession sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			unowned AgentMessage[] items_arr = (AgentMessage[]) items;
			items_arr.length = messages.size;

			sink.post_messages.begin (items_arr, 0, delivery_cancellable);

			free (items);
		}

		private async void deliver_batch (AgentSession sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			bool success = false;
			pending_deliveries++;
			try {
				int n = messages.size;

				foreach (var message in messages)
					message.delivery_attempts++;

				unowned AgentMessage[] items_arr = (AgentMessage[]) items;
				items_arr.length = n;

				uint batch_id = messages[n - 1].serial;

				yield sink.post_messages (items_arr, batch_id, delivery_cancellable);

				success = true;
			} catch (GLib.Error e) {
				pending_messages.add_all (messages);
				pending_messages.sort ((a, b) => a.serial - b.serial);
			} finally {
				pending_deliveries--;
				if (pending_deliveries == 0 && success)
					next_serial = 1;

				free (items);
			}
		}

		private class PendingMessage {
			public int serial;
			public AgentMessageKind kind;
			public AgentScriptId script_id;
			public string text;
			public Bytes? data;
			public uint delivery_attempts;

			public PendingMessage (int serial, AgentMessageKind kind, AgentScriptId script_id, string text,
					Bytes? data = null) {
				this.serial = serial;
				this.kind = kind;
				this.script_id = script_id;
				this.text = text;
				this.data = data;
			}

			public size_t estimate_size_in_bytes () {
				return sizeof (AgentMessage) + text.length + 1 + ((data != null) ? data.length : 0);
			}
		}

		internal void _release_script (AgentScriptId script_id) {
			var script_did_exist = scripts.unset (script_id);
			assert (script_did_exist);
		}

		private void check_open () throws Error {
			switch (state) {
				case ATTACHED:
					break;
				case INTERRUPTED:
					throw new Error.INVALID_OPERATION ("Session was interrupted; call resume()");
				case DETACHED:
					throw new Error.INVALID_OPERATION ("Session is gone");
			}
		}

		internal void _on_detached (SessionDetachReason reason, CrashInfo crash) {
			if (persist_timeout != 0 && reason == CONNECTION_TERMINATED) {
				if (state != ATTACHED)
					return;
				state = INTERRUPTED;
				delivery_cancellable.cancel ();
				detached (reason, null);
			} else {
				_do_close.begin (reason, crash, false, null);
			}
		}

		internal async void _do_close (SessionDetachReason reason, CrashInfo crash, bool may_block,
				Cancellable? cancellable) throws IOError {
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

			state = DETACHED;

			try {
				foreach (var script in scripts.values.to_array ())
					yield script._do_close (may_block, cancellable);

				if (may_block)
					close_session_and_peer_connection.begin (cancellable);
				else
					discard_peer_connection ();

				yield device._release_session (this, may_block, cancellable);

				detached (reason, Crash.from_info (crash));

				close_request.resolve (true);
			} catch (IOError e) {
				close_request.reject (e);
				close_request = null;
				throw e;
			}
		}

		private async void close_session_and_peer_connection (Cancellable? cancellable) throws IOError {
			try {
				yield active_session.close (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED) {
					discard_peer_connection ();
					return;
				}
			}

			yield teardown_peer_connection (cancellable);
		}

		private void begin_migration (AgentSession new_session) {
			obsolete_session = active_session;
			active_session = new_session;
		}

#if HAVE_NICE
		private void cancel_migration (AgentSession new_session) {
			active_session = obsolete_session;
			obsolete_session = null;
		}
#endif

		public DBusConnection _get_connection () {
			return ((DBusProxy) active_session).g_connection;
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}
		}
	}

	public class Script : Object {
		public signal void destroyed ();
		public signal void message (string json, Bytes? data);

		private AgentScriptId id;
		private unowned Session session;

		private Promise<bool> close_request;

		private Gum.InspectorServer? inspector_server;

		internal Script (Session session, AgentScriptId script_id) {
			Object ();

			this.id = script_id;
			this.session = session;
		}

		public bool is_destroyed () {
			return close_request != null;
		}

		public async void load (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.active_session.load_script (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void load_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<LoadTask> ().execute (cancellable);
		}

		private class LoadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.load (cancellable);
			}
		}

		public async void unload (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield _do_close (true, cancellable);
		}

		public void unload_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<UnloadTask> ().execute (cancellable);
		}

		private class UnloadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.unload (cancellable);
			}
		}

		public async void eternalize (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.active_session.eternalize_script (id, cancellable);

				yield _do_close (false, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void eternalize_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EternalizeTask> ().execute (cancellable);
		}

		private class EternalizeTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.eternalize (cancellable);
			}
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
			if (close_request != null)
				return;

			session._post_to_agent (AgentMessageKind.SCRIPT, id, json, data);
		}

		public async void enable_debugger (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (inspector_server != null)
				throw new Error.INVALID_OPERATION ("Debugger is already enabled");

			inspector_server = (port != 0)
				? new Gum.InspectorServer.with_port (port)
				: new Gum.InspectorServer ();
			inspector_server.message.connect (on_debugger_message_from_frontend);

			try {
				yield session.active_session.enable_debugger (id, cancellable);
			} catch (GLib.Error e) {
				inspector_server = null;

				throw_dbus_error (e);
			}

			if (inspector_server != null) {
				try {
					inspector_server.start ();
				} catch (Gum.Error e) {
					inspector_server = null;

					try {
						yield session.active_session.disable_debugger (id, cancellable);
					} catch (GLib.Error e) {
					}

					throw new Error.ADDRESS_IN_USE ("%s", e.message);
				}
			}
		}

		public void enable_debugger_sync (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnableScriptDebuggerTask> ();
			task.port = port;
			task.execute (cancellable);
		}

		private class EnableScriptDebuggerTask : ScriptTask<void> {
			public uint16 port;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_debugger (port, cancellable);
			}
		}

		public async void disable_debugger (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (inspector_server == null)
				return;

			inspector_server.message.disconnect (on_debugger_message_from_frontend);
			inspector_server.stop ();
			inspector_server = null;

			try {
				yield session.active_session.disable_debugger (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_debugger_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableScriptDebuggerTask> ().execute (cancellable);
		}

		private class DisableScriptDebuggerTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_debugger (cancellable);
			}
		}

		private void on_debugger_message_from_frontend (string message) {
			session._post_to_agent (AgentMessageKind.DEBUGGER, id, message);
		}

		internal void on_debugger_message_from_backend (string message) {
			if (inspector_server != null)
				inspector_server.post_message (message);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Script is destroyed");
		}

		internal async void _do_close (bool may_block, Cancellable? cancellable) throws IOError {
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

			var parent = session;

			parent._release_script (id);

			if (inspector_server != null) {
				inspector_server.message.disconnect (on_debugger_message_from_frontend);
				inspector_server.stop ();
				inspector_server = null;
			}

			if (may_block) {
				try {
					yield parent.active_session.destroy_script (id, cancellable);
				} catch (GLib.Error e) {
				}
			}

			destroyed ();

			close_request.resolve (true);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ScriptTask<T> : AsyncTask<T> {
			public weak Script parent {
				get;
				construct;
			}
		}
	}

	public class PortalMembership : Object {
		private uint id;
		private Session session;

		internal PortalMembership (Session session, PortalMembershipId membership_id) {
			Object ();

			this.id = membership_id.handle;
			this.session = session;
		}

		public async void terminate (Cancellable? cancellable = null) throws Error, IOError {
			try {
				yield session.active_session.leave_portal (PortalMembershipId (id), cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void terminate_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<TerminateTask> ().execute (cancellable);
		}

		private class TerminateTask : PortalMembershipTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.terminate (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PortalMembershipTask<T> : AsyncTask<T> {
			public weak PortalMembership parent {
				get;
				construct;
			}
		}
	}

	public interface Injector : Object {
		public signal void uninjected (uint id);

		public static Injector new () {
#if HAVE_LOCAL_BACKEND
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			var helper = new WindowsHelperProcess (tempdir);
			return new Winjector (helper, true, tempdir);
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperProcess (tempdir);
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			var helper = new LinuxHelperProcess (tempdir);
			return new Linjector (helper, true, tempdir);
#endif
#if FREEBSD
			return new Binjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
#else
			assert_not_reached ();
#endif
		}

		public static Injector new_inprocess () {
#if HAVE_LOCAL_BACKEND
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			var helper = new WindowsHelperBackend (PrivilegeLevel.NORMAL);
			return new Winjector (helper, true, tempdir);
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperBackend ();
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			var helper = new LinuxHelperBackend ();
			return new Linjector (helper, true, tempdir);
#endif
#if FREEBSD
			return new Binjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
#else
			assert_not_reached ();
#endif
		}

		public abstract async void close (Cancellable? cancellable = null) throws IOError;

		public void close_sync (Cancellable? cancellable = null) throws IOError {
			try {
				((CloseTask) create<CloseTask> ()).execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : InjectorTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.close (cancellable);
			}
		}

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data,
			Cancellable? cancellable = null) throws Error, IOError;

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryFileTask> () as InjectLibraryFileTask;
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryFileTask : InjectorTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_file (pid, path, entrypoint, data, cancellable);
			}
		}

		public abstract async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data,
			Cancellable? cancellable = null) throws Error, IOError;

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryBlobTask> () as InjectLibraryBlobTask;
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryBlobTask : InjectorTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}
		}

		public abstract async void demonitor (uint id, Cancellable? cancellable = null) throws Error, IOError;

		public void demonitor_sync (uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<DemonitorTask> () as DemonitorTask;
			task.id = id;
			task.execute (cancellable);
		}

		private class DemonitorTask : InjectorTask<void> {
			public uint id;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.demonitor (id, cancellable);
			}
		}

		public abstract async uint demonitor_and_clone_state (uint id, Cancellable? cancellable = null) throws Error, IOError;

		public uint demonitor_and_clone_state_sync (uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<DemonitorAndCloneStateTask> () as DemonitorAndCloneStateTask;
			task.id = id;
			return task.execute (cancellable);
		}

		private class DemonitorAndCloneStateTask : InjectorTask<uint> {
			public uint id;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.demonitor_and_clone_state (id, cancellable);
			}
		}

		public abstract async void recreate_thread (uint pid, uint id, Cancellable? cancellable = null) throws Error, IOError;

		public void recreate_thread_sync (uint pid, uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RecreateThreadTask> () as RecreateThreadTask;
			task.pid = pid;
			task.id = id;
			task.execute (cancellable);
		}

		private class RecreateThreadTask : InjectorTask<void> {
			public uint pid;
			public uint id;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.recreate_thread (pid, id, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class InjectorTask<T> : AsyncTask<T> {
			public weak Injector parent {
				get;
				construct;
			}
		}
	}

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void on_pending_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Timeout.add (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = Thread.garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}
}

"""


```