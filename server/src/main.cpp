#include <arpa/inet.h>
#include <psp2/ctrl.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/libdbg.h>
#include <psp2/motion.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/power.h>
#include <psp2/sysmodule.h>
#include <psp2/touch.h>
#include <psp2/types.h>
#include <vita2d.h>

#include <cassert>
#include <climits>

#include "ctrl.hpp"
#include "net.hpp"

#include <common.h>

constexpr size_t NET_INIT_SIZE = 1 * 1024 * 1024;

vita2d_pgf *debug_font;
uint32_t text_color;

int main() {
  // Enabling analog, motion and touch support
  sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG_WIDE);
  sceMotionStartSampling();
  sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT,
                           SCE_TOUCH_SAMPLING_STATE_START);
  sceTouchSetSamplingState(SCE_TOUCH_PORT_BACK, SCE_TOUCH_SAMPLING_STATE_START);
  sceTouchEnableTouchForce(SCE_TOUCH_PORT_FRONT);
  sceTouchEnableTouchForce(SCE_TOUCH_PORT_BACK);

  // Initializing graphics stuffs
  vita2d_init();
  vita2d_set_clear_color(RGBA8(0x00, 0x00, 0x00, 0xFF));
  debug_font = vita2d_load_default_pgf();
  uint32_t text_color = RGBA8(0xFF, 0xFF, 0xFF, 0xFF);

  // Initializing network stuffs
  sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
  char vita_ip[INET_ADDRSTRLEN];
  int ret = sceNetShowNetstat();
  if ((unsigned)ret == SCE_NET_ERROR_ENOTINIT) {
    SceNetInitParam initparam;
    initparam.memory = malloc(NET_INIT_SIZE);
    initparam.size = NET_INIT_SIZE;
    initparam.flags = 0;
    ret = sceNetInit(&initparam);
  }
  sceNetCtlInit();
  SceNetCtlInfo info;

  auto ev_connect = sceKernelCreateEventFlag("ev_con", 0, 0, nullptr);
  NetThreadMessage net_message = {ev_connect};
  // Open the net thread with an event flag in argument to write the
  // connection state
  auto net_thread_id = sceKernelCreateThread(
      "NetThread", &net_thread, 0x10000100, 0x10000, 0, 0, nullptr);
  if (net_thread_id < 0) {
    SCE_DBG_LOG_ERROR("Error creating thread: 0x%08X", net_thread_id);
    return -1;
  }
  sceKernelStartThread(net_thread_id, sizeof(net_message), &net_message);

  // Reduce cpu and gpu frequency to save battery
  scePowerSetArmClockFrequency(25);
  scePowerSetBusClockFrequency(25);
  scePowerSetGpuClockFrequency(10);

  unsigned int events;
  sceNetCtlInetGetState(reinterpret_cast<int *>(&events));
  bool connected_to_network = events == SCE_NETCTL_STATE_CONNECTED;
  if (connected_to_network) {
    sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    snprintf(vita_ip, INET_ADDRSTRLEN, "%s", info.ip_address);
  }
  events = 0;

  SceUInt TIMEOUT = (SceUInt)UINT32_MAX;
  do {
    vita2d_start_drawing();
    vita2d_clear_screen();
    vita2d_pgf_draw_text(debug_font, 2, 20, text_color, 1.0,
                         "VitaPad v1.3 build from " __DATE__ ", " __TIME__);
    if (events & NetEvent::NET_CONNECT) {
      connected_to_network = true;
      sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
      snprintf(vita_ip, INET_ADDRSTRLEN, "%s", info.ip_address);
    } else if (events & NetEvent::NET_DISCONNECT) {
      connected_to_network = false;
    }

    if (connected_to_network) {
      vita2d_pgf_draw_textf(debug_font, 2, 60, text_color, 1.0,
                            "Listening on:\nIP: %s\nPort: %d", vita_ip,
                            NET_PORT);
    } else {
      vita2d_pgf_draw_text(debug_font, 2, 60, text_color, 1.0,
                           "Not connected to a network");
    }

    vita2d_pgf_draw_textf(debug_font, 2, 200, text_color, 1.0, "Status: %s",
                          events & NetEvent::PC_CONNECT ? "Connected"
                                                        : "Not connected");
    vita2d_end_drawing();
    vita2d_wait_rendering_done();
    vita2d_swap_buffers();
  } while (sceKernelWaitEventFlag(
               ev_connect,
               NetEvent::PC_CONNECT | NetEvent::PC_DISCONNECT |
                   NetEvent::NET_CONNECT | NetEvent::NET_DISCONNECT,
               SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR, &events, &TIMEOUT) == 0);

  sceNetCtlTerm();
  sceNetTerm();
  sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);

  vita2d_fini();
  vita2d_free_pgf(debug_font);
  return 1;
}
