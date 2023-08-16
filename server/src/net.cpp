#include <psp2/kernel/threadmgr.h>

#include <assert.h>
#include <common.h>

#include "client.hpp"
#include "ctrl.hpp"
#include "net.hpp"

constexpr size_t MAX_EPOLL_EVENTS = 10;
constexpr time_t MAX_HEARTBEAT_INTERVAL = 25;
constexpr time_t SECOND_IN_MICROS = 1000 * 1000;

static int send_all(int fd, const void *buf, unsigned int size) {
  const char *buf_ptr = static_cast<const char *>(buf);
  int bytes_sent = 0;

  while (size > 0) {
    bytes_sent = sceNetSend(fd, buf_ptr, size, 0);
    if (bytes_sent < 0)
      return bytes_sent;

    buf_ptr += bytes_sent;
    size -= bytes_sent;
  }

  return bytes_sent;
}

static void handle_ingoing_data(Client &client) {
  constexpr size_t BUFFER_SIZE = 1024;

  uint8_t buffer[BUFFER_SIZE];
  int received;
  while ((received = sceNetRecv(client.ctrl_fd(), buffer, BUFFER_SIZE, 0)) >
         0) {
    client.add_to_buffer(buffer, received);
  }

  SCE_DBG_LOG_DEBUG("Received %i bytes from %s", received, client.ip());

  while (client.handle_heartbeat() || client.handle_data())
    ;

  if (received <= 0) {
    switch ((unsigned)received) {
    case SCE_NET_ERROR_EWOULDBLOCK:
      break;
    default:
      throw net::NetException(received);
    }
  }
}

static void send_handshake_response(Client &client, uint16_t port,
                                    uint32_t heartbeat_interval) {
  flatbuffers::FlatBufferBuilder builder;
  auto handshake_confirm = NetProtocol::CreateHandshake(
      builder, NetProtocol::Endpoint::Server, port, heartbeat_interval);
  auto packet =
      NetProtocol::CreatePacket(builder, NetProtocol::PacketContent::Handshake,
                                handshake_confirm.Union());
  builder.FinishSizePrefixed(packet);

  int sent =
      send_all(client.ctrl_fd(), builder.GetBufferPointer(), builder.GetSize());

  if (sent <= 0) {
    throw net::NetException(sent);
  }

  client.set_state(Client::State::Connected);
}

static void disconnect_client(std::optional<Client> &client, SceUID ev_flag) {
  sceKernelSetEventFlag(ev_flag, NetEvent::PC_DISCONNECT);
  if (!client)
    return;

  SCE_DBG_LOG_INFO("Client %s disconnected", client->ip());
  client.reset();
}

static void add_client(int server_tcp_fd, SceUID epoll,
                       std::optional<Client> &client,
                       SceUID ev_flag_connect_state) {
  SceNetSockaddrIn clientaddr;
  unsigned int addrlen = sizeof(clientaddr);
  int client_fd =
      sceNetAccept(server_tcp_fd, (SceNetSockaddr *)&clientaddr, &addrlen);
  if (client_fd >= 0) {
    client.emplace(client_fd, epoll);

    SceNetEpollEvent ev = {};
    ev.events = SCE_NET_EPOLLIN | SCE_NET_EPOLLOUT | SCE_NET_EPOLLHUP |
                SCE_NET_EPOLLERR;
    ev.data.u32 = static_cast<decltype(ev.data.u32)>(SocketType::CLIENT);
    auto nbio = 1;
    sceNetSetsockopt(client_fd, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nbio,
                     sizeof(nbio));

    sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_ADD, client_fd, &ev);
    sceKernelSetEventFlag(ev_flag_connect_state, NetEvent::PC_CONNECT);
  }
}

static void refuse_client(int server_tcp_fd) {
  SceNetSockaddrIn clientaddr;
  auto clientaddr_size = sizeof(clientaddr);
  auto client_fd = sceNetAccept(server_tcp_fd,
                                reinterpret_cast<SceNetSockaddr *>(&clientaddr),
                                &clientaddr_size);
  if (client_fd >= 0) {
    sceNetSocketClose(client_fd);
  }
}

struct NetCtlCallbackData {
  SceUID event_flag_netctl;
};

enum NetCtlEvents {
  Connected = 1,
  Disconnected = 2,
};

void *netctl_cb(int state, void *arg) {
  auto data = static_cast<NetCtlCallbackData *>(arg);

  switch (state) {
  case SCE_NETCTL_STATE_DISCONNECTED:
  case SCE_NETCTL_STATE_CONNECTING:
  case SCE_NETCTL_STATE_FINALIZING:
    sceKernelSetEventFlag(data->event_flag_netctl, NetCtlEvents::Disconnected);
    break;
  case SCE_NETCTL_STATE_CONNECTED:
    sceKernelSetEventFlag(data->event_flag_netctl, NetCtlEvents::Connected);
    break;
  default:
    break;
  }

  return nullptr;
}

int net_thread(__attribute__((unused)) unsigned int arglen, void *argp) {
  assert(arglen == sizeof(NetThreadMessage));

  NetThreadMessage *message = static_cast<NetThreadMessage *>(argp);

  auto server_tcp_fd =
      sceNetSocket("SERVER_SOCKET", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
  SceNetSockaddrIn serveraddr;
  serveraddr.sin_family = SCE_NET_AF_INET;
  serveraddr.sin_addr.s_addr = sceNetHtonl(SCE_NET_INADDR_ANY);
  serveraddr.sin_port = sceNetHtons(NET_PORT);
  sceNetBind(server_tcp_fd, reinterpret_cast<SceNetSockaddr *>(&serveraddr),
             sizeof(serveraddr));

  auto nbio = 1;
  sceNetSetsockopt(server_tcp_fd, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nbio,
                   sizeof(nbio));
  sceNetListen(server_tcp_fd, 1);

  auto server_udp_fd =
      sceNetSocket("SERVER_UDP_SOCKET", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
  sceNetBind(server_udp_fd, reinterpret_cast<SceNetSockaddr *>(&serveraddr),
             sizeof(serveraddr));

  std::optional<Client> client;

  int cbid;
  auto timeout = MIN_POLLING_INTERVAL_MICROS;
  auto connect_state = sceKernelCreateEventFlag("ev_netctl", 0, 0, nullptr);
  auto netctl_cb_data = NetCtlCallbackData{connect_state};
  sceNetCtlInetRegisterCallback(&netctl_cb, &netctl_cb_data, &cbid);

  SceUID epoll = sceNetEpollCreate("SERVER_EPOLL", 0);

  SceNetEpollEvent ev = {};
  ev.events = SCE_NET_EPOLLIN;
  ev.data.u32 = static_cast<decltype(ev.data.u32)>(SocketType::SERVER);
  sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_ADD, server_tcp_fd, &ev);

  SceNetEpollEvent events[MAX_EPOLL_EVENTS];
  int n;

  while ((n = sceNetEpollWaitCB(epoll, events, MAX_EPOLL_EVENTS, timeout)) >=
         0) {
    sceNetCtlCheckCallback();
    unsigned int event;
    if (sceKernelPollEventFlag(
            connect_state, NetCtlEvents::Connected | NetCtlEvents::Disconnected,
            SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR, &event) == 0) {
      switch (event) {
      case NetCtlEvents::Connected:
        SCE_DBG_LOG_INFO("Connected to internet");
        sceNetBind(server_tcp_fd, (SceNetSockaddr *)&serveraddr,
                   sizeof(serveraddr));
        sceNetListen(server_tcp_fd, 1);
        sceNetBind(server_udp_fd,
                   reinterpret_cast<SceNetSockaddr *>(&serveraddr),
                   sizeof(serveraddr));
        sceKernelSetEventFlag(message->ev_flag_connect_state,
                              NetEvent::NET_CONNECT);
        break;
      case NetCtlEvents::Disconnected:
        SCE_DBG_LOG_INFO("Disconnected from internet");
        sceKernelSetEventFlag(message->ev_flag_connect_state,
                              NetEvent::NET_DISCONNECT);
        client.reset();
        timeout = SECOND_IN_MICROS;
        break;
      }
    }

    for (size_t i = 0; i < (unsigned)n; i++) {
      auto ev = events[i];
      SocketType sock_type = static_cast<SocketType>(ev.data.u32);

      if (ev.events & SCE_NET_EPOLLHUP || ev.events & SCE_NET_EPOLLERR) {
        if (sock_type == SocketType::CLIENT) {
          disconnect_client(client, message->ev_flag_connect_state);
        }
      } else if (ev.events & SCE_NET_EPOLLIN) {
        if (sock_type == SocketType::SERVER) {
          if (!client) {
            add_client(server_tcp_fd, epoll, client,
                       message->ev_flag_connect_state);
          } else {
            refuse_client(server_tcp_fd);
          }

          if (client) {
            SCE_DBG_LOG_INFO("New client connected: %s", client->ip());
          }

          continue;
        }

        if (!client) {
          SCE_DBG_LOG_ERROR("Client is null and still is in epoll");
          continue;
        }

        try {
          SCE_DBG_LOG_INFO("Handling ingoing data from %s", client->ip());
          handle_ingoing_data(*client);
        } catch (const net::NetException &e) {
          if (e.error_code() == SCE_NET_ECONNRESET || e.error_code() == 0) {
            disconnect_client(client, message->ev_flag_connect_state);
          }
        } catch (const std::exception &e) {
          disconnect_client(client, message->ev_flag_connect_state);
        }
      } else if (ev.events & SCE_NET_EPOLLOUT) {
        if (sock_type == SocketType::SERVER) {
          continue;
        }

        switch (client->state()) {
        case Client::State::WaitingForServerConfirm: {
          try {
            send_handshake_response(*client, NET_PORT, MAX_HEARTBEAT_INTERVAL);
            SCE_DBG_LOG_INFO("Sent handshake response to %s", client->ip());

            SceNetEpollEvent ev = {};
            ev.events = SCE_NET_EPOLLIN | SCE_NET_EPOLLHUP | SCE_NET_EPOLLERR;
            ev.data.u32 =
                static_cast<decltype(ev.data.u32)>(SocketType::CLIENT);
            sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_MOD, client->ctrl_fd(),
                               &ev);
          } catch (const net::NetException &e) {
            if (e.error_code() == SCE_NET_ECONNRESET) {
              disconnect_client(client, message->ev_flag_connect_state);
            }
          } catch (const std::exception &e) {
            disconnect_client(client, message->ev_flag_connect_state);
          }

          break;
        }

        default:
          break;
        }
      }
    }

    if (!client)
      continue;

    if (client->time_since_last_heartbeat() > MAX_HEARTBEAT_INTERVAL) {
      disconnect_client(client, message->ev_flag_connect_state);
    }

    if (client->state() == Client::State::Connected &&
        client->is_polling_time_elapsed()) {
      auto pad_data = get_ctrl_as_netprotocol();

      client->update_sent_data_time();
      auto client_addr = client->data_conn_info();
      auto addrlen = sizeof(client_addr);
      sceNetSendto(server_udp_fd, pad_data.GetBufferPointer(),
                   pad_data.GetSize(), 0, &client_addr, addrlen);
    }

    timeout = client->remaining_polling_time();
  }

  sceNetCtlInetUnregisterCallback(cbid);

  return 0;
}
