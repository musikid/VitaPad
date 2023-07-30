#include <psp2/ctrl.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/motion.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <psp2/touch.h>
#include <psp2/types.h>
#include <vita2d.h>

#include <cassert>
#include <climits>

#include "ctrl.hpp"
#include "epoll.hpp"
#include "net.hpp"

#include <common.h>

#include <psp2/libdbg.h>

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
  sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
  snprintf(vita_ip, INET_ADDRSTRLEN, "%s", info.ip_address);
  SceNetInAddr vita_addr;
  sceNetInetPton(SCE_NET_AF_INET, info.ip_address, &vita_addr);

  SceUID ev_connect = sceKernelCreateEventFlag("ev_con", 0, 0, NULL);
  NetThreadMessage net_message = {ev_connect};
  // Open the main thread with an event flag in argument to write the
  // connection state
  SceUID main_thread_id = sceKernelCreateThread(
      "NetThread", &net_thread, 0x10000100, 0x10000, 0, 0, NULL);
  sceKernelStartThread(main_thread_id, sizeof(net_message), &net_message);

  unsigned int state = 0;
  SceUInt TIMEOUT = (SceUInt)UINT32_MAX;
  do {
    vita2d_start_drawing();
    vita2d_clear_screen();
    vita2d_pgf_draw_text(debug_font, 2, 20, text_color, 1.0,
                         "VitaPad v1.3 build from " __DATE__ ", " __TIME__);
    vita2d_pgf_draw_textf(debug_font, 2, 60, text_color, 1.0,
                          "Listening on:\nIP: %s\nPort: %d", vita_ip, NET_PORT);
    vita2d_pgf_draw_textf(debug_font, 2, 200, text_color, 1.0, "Status: %s",
                          state & ConnectionState::CONNECT ? "Connected"
                                                           : "Not connected");
    vita2d_end_drawing();
    vita2d_wait_rendering_done();
    vita2d_swap_buffers();
  } while (sceKernelWaitEventFlag(
               ev_connect,
               ConnectionState::CONNECT | ConnectionState::DISCONNECT,
               SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR, &state, &TIMEOUT) == 0);

  sceNetCtlTerm();
  sceNetTerm();
  sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);

  vita2d_fini();
  vita2d_free_pgf(debug_font);
  return 1;
}
