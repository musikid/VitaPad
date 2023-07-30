#include <psp2/kernel/threadmgr.h>

#include <assert.h>
#include <common.h>

#include "ctrl.hpp"
#include "epoll.hpp"
#include "net.hpp"

constexpr size_t MAX_EPOLL_EVENTS = 10;
constexpr time_t MAX_HEARTBEAT_INTERVAL = 60;

int send_all(int fd, const void *buf, unsigned int size) {
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

void handle_ingoing_data(ClientData &client) {
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

void send_handshake_response(ClientData &client, uint16_t port,
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

  client.set_state(ClientData::State::Connected);
}

void disconnect_client(std::shared_ptr<ClientData> client, SceUID ev_flag) {
  client->mark_for_removal();
  sceKernelSetEventFlag(ev_flag, ConnectionState::DISCONNECT);
  SCE_DBG_LOG_INFO("Client %s disconnected", client->ip());
}

void add_client(int server_tcp_fd, SceUID epoll,
                ClientsManager &clients_manager, SceUID ev_flag_connect_state) {
  SceNetSockaddrIn clientaddr;
  unsigned int addrlen = sizeof(clientaddr);
  int client_fd =
      sceNetAccept(server_tcp_fd, (SceNetSockaddr *)&clientaddr, &addrlen);
  if (client_fd >= 0) {
    auto client_data = std::make_shared<ClientData>(client_fd, epoll);
    clients_manager.add_client(client_data);
    auto member_ptr = std::make_unique<EpollMember>(client_data);
    client_data->set_member_ptr(std::move(member_ptr));

    SceNetEpollEvent ev = {};
    ev.events = SCE_NET_EPOLLIN | SCE_NET_EPOLLOUT | SCE_NET_EPOLLHUP |
                SCE_NET_EPOLLERR;
    ev.data.ptr = client_data->member_ptr().get();
    auto nbio = 1;
    sceNetSetsockopt(client_data->ctrl_fd(), SCE_NET_SOL_SOCKET,
                     SCE_NET_SO_NBIO, &nbio, sizeof(nbio));

    sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_ADD, client_data->ctrl_fd(),
                       &ev);
    sceKernelSetEventFlag(ev_flag_connect_state, ConnectionState::CONNECT);
  }
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
  sceNetBind(server_tcp_fd, (SceNetSockaddr *)&serveraddr, sizeof(serveraddr));

  auto nbio = 1;
  sceNetSetsockopt(server_tcp_fd, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nbio,
                   sizeof(nbio));
  sceNetListen(server_tcp_fd, 2);

  auto server_udp_fd =
      sceNetSocket("SERVER_UDP_SOCKET", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
  sceNetBind(server_udp_fd, (SceNetSockaddr *)&serveraddr, sizeof(serveraddr));

  ClientsManager clients_manager;
  SceUID epoll = sceNetEpollCreate("SERVER_EPOLL", 0);

  EpollMember server_ptr;
  SceNetEpollEvent ev = {};
  ev.events = SCE_NET_EPOLLIN;
  ev.data.ptr = &server_ptr;
  sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_ADD, server_tcp_fd, &ev);

  SceNetEpollEvent events[MAX_EPOLL_EVENTS];
  int n;

  while ((n = sceNetEpollWait(epoll, events, MAX_EPOLL_EVENTS,
                              MIN_POLLING_INTERVAL_MICROS)) >= 0) {
    for (size_t i = 0; i < (unsigned)n; i++) {
      auto ev = events[i];
      EpollMember *data = static_cast<EpollMember *>(ev.data.ptr);

      if (ev.events & SCE_NET_EPOLLHUP || ev.events & SCE_NET_EPOLLERR) {
        if (data->type == SocketType::CLIENT) {
          disconnect_client(data->client(), message->ev_flag_connect_state);
        }
      } else if (ev.events & SCE_NET_EPOLLIN) {
        if (data->type == SocketType::SERVER) {
          add_client(server_tcp_fd, epoll, clients_manager,
                     message->ev_flag_connect_state);
          SCE_DBG_LOG_INFO("New client connected: %s",
                           clients_manager.clients().back()->ip());
          continue;
        }

        auto client = data->client();
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
        if (data->type == SocketType::SERVER) {
          continue;
        }

        auto client = data->client();

        switch (client->state()) {
        case ClientData::State::WaitingForServerConfirm: {
          try {
            send_handshake_response(*client, NET_PORT, MAX_HEARTBEAT_INTERVAL);
            SCE_DBG_LOG_INFO("Sent handshake response to %s", client->ip());

            SceNetEpollEvent ev = {};
            ev.events = SCE_NET_EPOLLIN | SCE_NET_EPOLLHUP | SCE_NET_EPOLLERR;
            ev.data.ptr = client->member_ptr().get();
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

    auto clients = clients_manager.clients();

    if (clients.empty())
      continue;

    for (auto &client : clients) {
      if (client->time_since_last_heartbeat() > MAX_HEARTBEAT_INTERVAL) {
        disconnect_client(client, message->ev_flag_connect_state);
      }
    }

    clients_manager.remove_marked_clients();

    if (std::none_of(clients.begin(), clients.end(),
                     [](const std::shared_ptr<ClientData> &client) {
                       return client->state() == ClientData::State::Connected &&
                              client->is_polling_time_elapsed();
                     })) {
      continue;
    }

    flatbuffers::FlatBufferBuilder pad_data = get_ctrl_as_netprotocol();

    for (auto &client : clients) {
      if (client->state() == ClientData::State::Connected &&
          client->is_polling_time_elapsed()) {
        client->update_sent_data_time();
        auto client_addr = client->data_conn_info();
        auto addrlen = sizeof(client_addr);
        sceNetSendto(server_udp_fd, pad_data.GetBufferPointer(),
                     pad_data.GetSize(), 0, &client_addr, addrlen);
      }
    }
  }

  sceKernelSetEventFlag(message->ev_flag_connect_state,
                        ConnectionState::DISCONNECT);

  return 0;
}
