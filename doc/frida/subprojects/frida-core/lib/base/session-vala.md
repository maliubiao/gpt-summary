Response:
### 功能归纳

`session.vala` 文件是 Frida 动态插桩工具的核心部分，主要负责与目标进程的交互、进程管理、脚本注入、调试等功能。以下是该文件的主要功能归纳：

1. **进程管理**：
   - **枚举进程**：通过 `enumerate_processes` 方法获取系统中运行的进程列表。
   - **启动进程**：通过 `spawn` 方法启动一个新的进程，并可以指定启动选项。
   - **挂起/恢复进程**：通过 `resume` 和 `kill` 方法控制目标进程的执行状态。
   - **进程崩溃处理**：通过 `process_crashed` 信号处理目标进程的崩溃事件。

2. **脚本管理**：
   - **创建脚本**：通过 `create_script` 和 `create_script_from_bytes` 方法创建新的脚本。
   - **编译脚本**：通过 `compile_script` 方法编译脚本。
   - **加载/卸载脚本**：通过 `load_script` 和 `destroy_script` 方法加载和卸载脚本。
   - **脚本调试**：通过 `enable_debugger` 和 `disable_debugger` 方法启用或禁用脚本的调试功能。

3. **进程注入**：
   - **注入库文件**：通过 `inject_library_file` 方法将库文件注入到目标进程中。
   - **注入二进制数据**：通过 `inject_library_blob` 方法将二进制数据注入到目标进程中。

4. **调试功能**：
   - **调试器支持**：通过 `enable_debugger` 和 `disable_debugger` 方法启用或禁用调试器。
   - **调试消息处理**：通过 `post_message_from_debugger` 方法处理来自调试器的消息。

5. **信号处理**：
   - **进程信号**：通过 `spawn_added`、`spawn_removed`、`child_added`、`child_removed` 等信号处理进程的创建、销毁、子进程的添加和移除等事件。
   - **输出信号**：通过 `output` 信号处理目标进程的标准输出和标准错误输出。

6. **会话管理**：
   - **会话创建与销毁**：通过 `attach` 和 `reattach` 方法创建和重新附加会话。
   - **会话分离**：通过 `agent_session_detached` 信号处理会话分离事件。

7. **网络通信**：
   - **P2P 连接**：通过 `offer_peer_connection` 和 `add_candidates` 方法支持点对点连接。
   - **消息传输**：通过 `post_messages` 方法传输消息。

8. **权限管理**：
   - **权限验证**：通过 `authenticate` 方法进行权限验证。

### 涉及二进制底层和 Linux 内核的示例

1. **进程注入**：
   - 在 Linux 系统中，`inject_library_file` 方法可能会使用 `ptrace` 系统调用来附加到目标进程，并通过 `mmap` 和 `mprotect` 系统调用将库文件映射到目标进程的地址空间中。
   - 示例：`ptrace(PTRACE_ATTACH, pid, NULL, NULL)` 用于附加到目标进程，`mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)` 用于在目标进程中分配内存。

2. **调试功能**：
   - 在 Linux 系统中，调试功能可能依赖于 `ptrace` 系统调用来控制目标进程的执行，设置断点，读取和修改寄存器等。
   - 示例：`ptrace(PTRACE_PEEKTEXT, pid, addr, NULL)` 用于读取目标进程的内存，`ptrace(PTRACE_POKETEXT, pid, addr, data)` 用于修改目标进程的内存。

### LLDB 指令或 Python 脚本示例

假设我们要使用 LLDB 来复刻 `inject_library_file` 的功能，以下是一个简单的 LLDB Python 脚本示例：

```python
import lldb

def inject_library(pid, library_path):
    # 附加到目标进程
    target = lldb.SBTarget.CreateTarget(library_path)
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)

    # 分配内存
    size = os.path.getsize(library_path)
    allocated_memory = process.AllocateMemory(size, lldb.ePermissionsReadable | lldb.ePermissionsWritable | lldb.ePermissionsExecutable)

    # 将库文件写入目标进程的内存
    with open(library_path, 'rb') as f:
        library_data = f.read()
    process.WriteMemory(allocated_memory, library_data, lldb.SBError())

    # 修改内存权限为可执行
    process.SetMemoryPermissions(allocated_memory, size, lldb.ePermissionsExecutable)

    # 执行库中的入口函数
    entry_point = allocated_memory + 0x1000  # 假设入口函数在库文件的偏移 0x1000 处
    process.SetPC(entry_point)
    process.Continue()

# 使用示例
inject_library(1234, "/path/to/library.so")
```

### 假设输入与输出

1. **输入**：
   - `pid`：目标进程的 PID。
   - `library_path`：要注入的库文件路径。

2. **输出**：
   - 库文件被成功注入到目标进程中，并且目标进程开始执行库中的代码。

### 用户常见的使用错误

1. **权限不足**：
   - 用户尝试注入一个需要 root 权限的进程，但没有以 root 身份运行 Frida。
   - 示例：`Error: Permission denied`。

2. **目标进程不存在**：
   - 用户尝试附加到一个不存在的进程。
   - 示例：`Error: Process not found`。

3. **库文件路径错误**：
   - 用户提供的库文件路径不存在或无法访问。
   - 示例：`Error: Library file not found`。

### 用户操作如何一步步到达这里

1. **启动 Frida**：用户启动 Frida 并连接到目标设备。
2. **选择目标进程**：用户通过 `enumerate_processes` 方法选择要调试的目标进程。
3. **附加到进程**：用户通过 `attach` 方法附加到目标进程。
4. **注入脚本**：用户通过 `create_script` 方法创建并注入脚本。
5. **调试脚本**：用户通过 `enable_debugger` 方法启用调试功能，并通过 `post_message_from_debugger` 方法发送调试消息。
6. **处理输出**：用户通过 `output` 信号处理目标进程的输出。

### 总结

`session.vala` 文件实现了 Frida 的核心功能，包括进程管理、脚本注入、调试、信号处理等。它涉及到底层的系统调用和内核功能，特别是在进程注入和调试方面。通过 LLDB 或类似的调试工具，可以复刻部分功能，但需要注意权限和目标进程的状态。用户在使用时可能会遇到权限不足、目标进程不存在等常见错误，需要仔细检查操作步骤和权限设置。
### 提示词
```
这是目录为frida/subprojects/frida-core/lib/base/session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
	[DBus (name = "re.frida.HostSession16")]
	public interface HostSession : Object {
		public abstract async void ping (uint interval_seconds, Cancellable? cancellable) throws GLib.Error;

		public abstract async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws GLib.Error;
		public abstract async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public abstract async void resume (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async void kill (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void reattach (AgentSessionId id, Cancellable? cancellable) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
			Cancellable? cancellable) throws GLib.Error;

		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);
		public signal void child_added (HostChildInfo info);
		public signal void child_removed (HostChildInfo info);
		public signal void process_crashed (CrashInfo crash);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash);
		public signal void uninjected (InjectorPayloadId id);
	}

	[DBus (name = "re.frida.AgentSessionProvider16")]
	public interface AgentSessionProvider : Object {
		public abstract async void open (AgentSessionId id, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
#if !WINDOWS
		public abstract async void migrate (AgentSessionId id, GLib.Socket to_socket, Cancellable? cancellable) throws GLib.Error;
#endif
		public abstract async void unload (Cancellable? cancellable) throws GLib.Error;

		public signal void opened (AgentSessionId id);
		public signal void closed (AgentSessionId id);
		public signal void eternalized ();
		public signal void child_gating_changed (uint subscriber_count);
	}

	[DBus (name = "re.frida.AgentSession16")]
	public interface AgentSession : Object {
		public abstract async void close (Cancellable? cancellable) throws GLib.Error;

		public abstract async void interrupt (Cancellable? cancellable) throws GLib.Error;
		public abstract async void resume (uint rx_batch_id, Cancellable? cancellable, out uint tx_batch_id) throws GLib.Error;

		public abstract async void enable_child_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_child_gating (Cancellable? cancellable) throws GLib.Error;

		public abstract async AgentScriptId create_script (string source, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes (uint8[] bytes, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] compile_script (string source, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] snapshot_script (string embed_script, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void post_messages (AgentMessage[] messages, uint batch_id,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async PortalMembershipId join_portal (string address, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
			Cancellable? cancellable, out string answer_sdp) throws GLib.Error;
		public abstract async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws GLib.Error;
		public abstract async void notify_candidate_gathering_done (Cancellable? cancellable) throws GLib.Error;
		public abstract async void begin_migration (Cancellable? cancellable) throws GLib.Error;
		public abstract async void commit_migration (Cancellable? cancellable) throws GLib.Error;
		public signal void new_candidates (string[] candidate_sdps);
		public signal void candidate_gathering_done ();
	}

	[DBus (name = "re.frida.AgentController16")]
	public interface AgentController : Object {
#if !WINDOWS
		public abstract async HostChildId prepare_to_fork (uint parent_pid, Cancellable? cancellable, out uint parent_injectee_id,
			out uint child_injectee_id, out GLib.Socket child_socket) throws GLib.Error;
#endif

		public abstract async HostChildId prepare_to_specialize (uint pid, string identifier, Cancellable? cancellable,
			out uint specialized_injectee_id, out string specialized_pipe_address) throws GLib.Error;

		public abstract async void recreate_agent_thread (uint pid, uint injectee_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async void prepare_to_exec (HostChildInfo info, Cancellable? cancellable) throws GLib.Error;
		public abstract async void cancel_exec (uint pid, Cancellable? cancellable) throws GLib.Error;

		public abstract async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state,
			Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "re.frida.AgentMessageSink16")]
	public interface AgentMessageSink : Object {
		public abstract async void post_messages (AgentMessage[] messages, uint batch_id,
			Cancellable? cancellable) throws GLib.Error;
	}

	public struct AgentMessage {
		public AgentMessageKind kind;

		public AgentScriptId script_id;

		public string text;

		public bool has_data;
		public uint8[] data;

		public AgentMessage (AgentMessageKind kind, AgentScriptId script_id, string text, bool has_data, uint8[] data) {
			this.kind = kind;
			this.script_id = script_id;
			this.text = text;
			this.has_data = has_data;
			this.data = data;
		}
	}

	public enum AgentMessageKind {
		SCRIPT = 1,
		DEBUGGER
	}

	public class AgentMessageTransmitter : Object {
		public signal void closed ();
		public signal void new_candidates (string[] candidate_sdps);
		public signal void candidate_gathering_done ();

		public weak AgentSession agent_session {
			get;
			construct;
		}

		public uint persist_timeout {
			get;
			construct;
		}

		public AgentMessageSink? message_sink {
			get;
			set;
		}

		public MainContext frida_context {
			get;
			construct;
		}

		public MainContext dbus_context {
			get;
			construct;
		}

		private Promise<bool>? close_request;

		private State state = LIVE;

		private TimeoutSource? expiry_timer;

		private uint last_rx_batch_id = 0;
		private Gee.LinkedList<PendingMessage> pending_messages = new Gee.LinkedList<PendingMessage> ();
		private int next_serial = 1;
		private uint pending_deliveries = 0;
		private Cancellable delivery_cancellable = new Cancellable ();

#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private SctpConnection? nice_iostream;
		private DBusConnection? nice_connection;
		private uint nice_registration_id;
#endif
		private AgentMessageSink? nice_message_sink;
		private Cancellable nice_cancellable = new Cancellable ();

		private enum State {
			LIVE,
			INTERRUPTED
		}

		public AgentMessageTransmitter (AgentSession agent_session, uint persist_timeout, MainContext frida_context,
				MainContext dbus_context) {
			Object (
				agent_session: agent_session,
				persist_timeout: persist_timeout,
				frida_context: frida_context,
				dbus_context: dbus_context
			);
		}

		construct {
			assert (frida_context != null);
			assert (dbus_context != null);
		}

		public async void close (Cancellable? cancellable) throws IOError {
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

			nice_cancellable.cancel ();

			delivery_cancellable.cancel ();

			yield teardown_peer_connection_and_emit_closed ();

			message_sink = null;

			close_request.resolve (true);
		}

		public void check_okay_to_receive () throws Error {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");
		}

		public void interrupt () throws Error {
			if (persist_timeout == 0 || expiry_timer != null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			state = INTERRUPTED;
			delivery_cancellable.cancel ();

			expiry_timer = new TimeoutSource.seconds (persist_timeout);
			expiry_timer.set_callback (() => {
				close.begin (null);
				return false;
			});
			expiry_timer.attach (frida_context);
		}

		public void resume (uint rx_batch_id, out uint tx_batch_id) throws Error {
			if (persist_timeout == 0 || expiry_timer == null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			if (rx_batch_id != 0) {
				PendingMessage? m;
				while ((m = pending_messages.peek ()) != null && m.delivery_attempts > 0 && m.serial <= rx_batch_id) {
					pending_messages.poll ();
				}
			}

			expiry_timer.destroy ();
			expiry_timer = null;

			delivery_cancellable = new Cancellable ();
			state = LIVE;

			schedule_on_frida_thread (() => {
				maybe_deliver_pending_messages ();
				return false;
			});

			tx_batch_id = last_rx_batch_id;
		}

		public void notify_rx_batch_id (uint batch_id) throws Error {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");

			last_rx_batch_id = batch_id;
		}

#if HAVE_NICE
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			var offer = PeerSessionDescription.parse (offer_sdp);

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, ICE_TRICKLE);
			agent.set_software ("Frida");
			agent.controlling_mode = false;
			agent.ice_tcp = false;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");
			agent.set_remote_credentials (stream_id, offer.ice_ufrag, offer.ice_pwd);

			yield PeerConnection.configure_agent (agent, stream_id, component_id, PeerOptions._deserialize (peer_options),
				cancellable);

			uint8[] cert_der;
			string cert_pem, key_pem;
			yield generate_certificate (out cert_der, out cert_pem, out key_pem);

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem + key_pem, -1);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var answer = new PeerSessionDescription ();
			answer.session_id = PeerSessionId.generate ();
			agent.get_local_credentials (stream_id, out answer.ice_ufrag, out answer.ice_pwd);
			answer.ice_trickle = offer.ice_trickle;
			answer.fingerprint = PeerConnection.compute_certificate_fingerprint (cert_der);
			answer.setup = (offer.setup != ACTIVE) ? PeerSetup.ACTIVE : PeerSetup.ACTPASS;
			answer.sctp_port = offer.sctp_port;
			answer.max_message_size = offer.max_message_size;

			answer_sdp = answer.to_sdp ();

			if (nice_agent != null)
				throw new Error.INVALID_OPERATION ("Peer connection already exists");

			nice_agent = agent;
			nice_stream_id = stream_id;
			nice_component_id = component_id;

			schedule_on_dbus_thread (() => {
				open_peer_connection.begin (certificate, offer, cancellable);
				return false;
			});
		}

		private async void teardown_peer_connection_and_emit_closed () {
			schedule_on_frida_thread (() => {
				if (nice_agent != null)
					close_nice_resources_and_emit_closed.begin ();
				else
					closed ();
				return Source.REMOVE;
			});
		}

		private async void close_nice_resources_and_emit_closed () {
			yield close_nice_resources (true);

			closed ();
		}

		private async void close_nice_resources (bool connection_still_alive) {
			Nice.Agent? agent = nice_agent;
			DBusConnection? conn = nice_connection;

			discard_nice_resources ();

			if (conn != null && connection_still_alive) {
				try {
					yield conn.flush ();
					yield conn.close ();
				} catch (GLib.Error e) {
				}
			}

			if (agent != null) {
				schedule_on_dbus_thread (() => {
					agent.close_async.begin ();

					schedule_on_frida_thread (() => {
						close_nice_resources.callback ();
						return false;
					});

					return false;
				});
				yield;
			}
		}

		private void discard_nice_resources () {
			nice_cancellable.cancel ();
			nice_cancellable = new Cancellable ();

			nice_message_sink = null;

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

		private async void open_peer_connection (TlsCertificate certificate, PeerSessionDescription offer,
				Cancellable? cancellable) {
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
								int n = stolen_candidates.size;
								var sdps = new string[n + 1];
								for (int i = 0; i != n; i++)
									sdps[i] = stolen_candidates[i];

								new_candidates (sdps[0:n]);

								return false;
							});

							return false;
						});
					}
				});

				gathering_handler = agent.candidate_gathering_done.connect (stream_id => {
					schedule_on_dbus_thread (() => {
						schedule_on_frida_thread (() => {
							candidate_gathering_done ();
							return false;
						});
						return false;
					});
				});

				if (!agent.gather_candidates (nice_stream_id))
					throw new Error.NOT_SUPPORTED ("Unable to gather local candidates");

				var socket = new PeerSocket (agent, nice_stream_id, nice_component_id);

				if (offer.setup == ACTIVE) {
					tc = DtlsServerConnection.new (socket, certificate);
				} else {
					tc = DtlsClientConnection.new (socket, null);
					tc.set_certificate (certificate);
				}
				tc.set_database (null);
				accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return PeerConnection.compute_certificate_fingerprint (peer_cert.certificate.data) == offer.fingerprint;
				});
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);

				nice_iostream = new SctpConnection (tc, offer.setup, offer.sctp_port, offer.max_message_size);

				schedule_on_frida_thread (() => {
					complete_peer_connection.begin ();
					return false;
				});
			} catch (GLib.Error e) {
				schedule_on_frida_thread (() => {
					close_nice_resources.begin (false);
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

		private async void complete_peer_connection () {
			try {
				nice_connection = yield new DBusConnection (nice_iostream, null, DELAY_MESSAGE_PROCESSING, null,
					nice_cancellable);
				nice_connection.on_closed.connect (on_nice_connection_closed);

				try {
					nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_SESSION, agent_session);
				} catch (IOError io_error) {
					assert_not_reached ();
				}

				nice_connection.start_message_processing ();

				nice_message_sink = yield nice_connection.get_proxy (null, ObjectPath.AGENT_MESSAGE_SINK,
					DO_NOT_LOAD_PROPERTIES, null);
			} catch (GLib.Error e) {
				close_nice_resources.begin (false);
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			switch (state) {
				case FAILED:
					nice_cancellable.cancel ();
					break;
				default:
					break;
			}
		}

		public void add_candidates (string[] candidate_sdps) throws Error {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				throw new Error.INVALID_OPERATION ("No peer connection in progress");

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

		public void notify_candidate_gathering_done () throws Error {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				throw new Error.INVALID_OPERATION ("No peer connection in progress");

			schedule_on_dbus_thread (() => {
				agent.peer_candidate_gathering_done (nice_stream_id);

				return false;
			});
		}

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			handle_nice_connection_closure.begin ();
		}

		private async void handle_nice_connection_closure () {
			yield close_nice_resources (false);

			if (persist_timeout != 0) {
				try {
					interrupt ();
				} catch (Error e) {
				}
			} else {
				close.begin (null);
			}
		}
#else
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection_and_emit_closed () {
			schedule_on_frida_thread (() => {
				closed ();
				return Source.REMOVE;
			});
		}

		public void add_candidates (string[] candidate_sdps) throws Error {
		}

		public void notify_candidate_gathering_done () throws Error {
		}
#endif

		public void begin_migration () {
			state = INTERRUPTED;
		}

		public void commit_migration () {
			if (expiry_timer != null)
				return;

			state = LIVE;

			maybe_deliver_pending_messages ();
		}

		public void post_message_from_script (AgentScriptId script_id, string json, Bytes? data) {
			pending_messages.offer (new PendingMessage (next_serial++, AgentMessageKind.SCRIPT, script_id, json, data));
			maybe_deliver_pending_messages ();
		}

		public void post_message_from_debugger (AgentScriptId script_id, string message) {
			pending_messages.offer (new PendingMessage (next_serial++, AgentMessageKind.DEBUGGER, script_id, message));
			maybe_deliver_pending_messages ();
		}

		private void maybe_deliver_pending_messages () {
			if (state != LIVE)
				return;

			AgentMessageSink? sink = (nice_message_sink != null) ? nice_message_sink : message_sink;
			if (sink == null)
				return;

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

		private void emit_batch (AgentMessageSink sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			unowned AgentMessage[] items_arr = (AgentMessage[]) items;
			items_arr.length = messages.size;

			sink.post_messages.begin (items_arr, 0, delivery_cancellable);

			free (items);
		}

		private async void deliver_batch (AgentMessageSink sink, Gee.ArrayList<PendingMessage> messages, void * items) {
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

		protected void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		protected void schedule_on_dbus_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
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
	}

	[DBus (name = "re.frida.TransportBroker16")]
	public interface TransportBroker : Object {
		public abstract async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
			out string token) throws GLib.Error;
	}

	[DBus (name = "re.frida.PortalSession16")]
	public interface PortalSession : Object {
		public abstract async void join (HostApplicationInfo app, SpawnStartState current_state,
			AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options, Cancellable? cancellable,
			out SpawnStartState next_state) throws GLib.Error;
		public signal void resume ();
		public signal void kill ();
	}

	[DBus (name = "re.frida.BusSession16")]
	public interface BusSession : Object {
		public abstract async void attach (Cancellable? cancellable) throws GLib.Error;
		public abstract async void post (string json, bool has_data, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public signal void message (string json, bool has_data, uint8[] data);
	}

	[DBus (name = "re.frida.AuthenticationService16")]
	public interface AuthenticationService : Object {
		public abstract async string authenticate (string token, Cancellable? cancellable) throws GLib.Error;
	}

	public class StaticAuthenticationService : Object, AuthenticationService {
		public string token_hash {
			get;
			construct;
		}

		public StaticAuthenticationService (string token) {
			Object (token_hash: Checksum.compute_for_string (SHA256, token));
		}

		public async string authenticate (string token, Cancellable? cancellable) throws Error, IOError {
			string input_hash = Checksum.compute_for_string (SHA256, token);

			uint accumulator = 0;
			for (uint i = 0; i != input_hash.length; i++) {
				accumulator |= input_hash[i] ^ token_hash[i];
			}

			if (accumulator != 0)
				throw new Error.INVALID_ARGUMENT ("Incorrect token");

			return "{}";
		}
	}

	public class NullAuthenticationService : Object, AuthenticationService {
		public async string authenticate (string token, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Authentication not expected");
		}
	}

	public class UnauthorizedHostSession : Object, HostSession {
		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	public class UnauthorizedPortalSession : Object, PortalSession {
		public async void join (HostApplicationInfo app, SpawnStartState current_state,
				AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options,
				Cancellable? cancellable, out SpawnStartState next_state) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	public class UnauthorizedBusSession : Object, BusSession {
		public async void attach (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void post (string json, bool has_data, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	[NoReturn]
	private void throw_not_authorized () throws Error {
		throw new Error.PERMISSION_DENIED ("Not authorized, authentication required");
	}

	public enum Realm {
		NATIVE,
		EMULATED;

		public static Realm from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Realm> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Realm> (this);
		}
	}

	public enum SpawnStartState {
		RUNNING,
		SUSPENDED;

		public static SpawnStartState from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SpawnStartState> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SpawnStartState> (this);
		}
	}

	public enum UnloadPolicy {
		IMMEDIATE,
		RESIDENT,
		DEFERRED;

		public static UnloadPolicy from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<UnloadPolicy> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<UnloadPolicy> (this);
		}
	}

	public struct InjectorPayloadId {
		public uint handle;

		public InjectorPayloadId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (InjectorPayloadId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (InjectorPayloadId? a, InjectorPayloadId? b) {
			return a.handle == b.handle;
		}
	}

	public struct MappedLibraryBlob {
		public uint64 address;
		public uint size;
		public uint allocated_size;

		public MappedLibraryBlob (uint64 address, uint size, uint allocated_size) {
			this.address = address;
			this.size = size;
			this.allocated_size = allocated_size;
		}
	}

#if DARWIN
	public struct DarwinInjectorState {
		public Gum.MemoryRange? mapped_range;
	}
#endif

#if LINUX
	public struct LinuxInjectorState {
		public int frida_ctrlfd;
		public int agent_ctrlfd;
	}
#endif

#if LINUX || FREEBSD
	public struct PosixInjectorState {
		public int fifo_fd;
	}
#endif

	public enum SessionDetachReason {
		APPLICATION_REQUESTED = 1,
		PROCESS_REPLACED,
		PROCESS_TERMINATED,
		CONNECTION_TERMINATED,
		DEVICE_LOST;

		public static SessionDetachReason from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SessionDetachReason> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SessionDetachReason> (this);
		}
	}

	[DBus (name = "re.frida.Error")]
	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_FOUND,
		PROCESS_NOT_RESPONDING,
		INVALID_ARGUMENT,
		INVALI
```