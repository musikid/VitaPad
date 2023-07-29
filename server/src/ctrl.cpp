#include <assert.h>

#include <psp2/ctrl.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/motion.h>
#include <psp2/touch.h>
#include <psp2/types.h>

#include "ctrl.hpp"

NetProtocol::ButtonsData convert_pad_data(const SceCtrlData &data) {
  return NetProtocol::ButtonsData(
      (data.buttons & SCE_CTRL_SELECT) > 0, (data.buttons & SCE_CTRL_START) > 0,
      (data.buttons & SCE_CTRL_UP) > 0, (data.buttons & SCE_CTRL_RIGHT) > 0,
      (data.buttons & SCE_CTRL_DOWN) > 0, (data.buttons & SCE_CTRL_LEFT) > 0,
      (data.buttons & SCE_CTRL_LTRIGGER) > 0,
      (data.buttons & SCE_CTRL_RTRIGGER) > 0,
      (data.buttons & SCE_CTRL_TRIANGLE) > 0,
      (data.buttons & SCE_CTRL_CIRCLE) > 0, (data.buttons & SCE_CTRL_CROSS) > 0,
      (data.buttons & SCE_CTRL_SQUARE) > 0);
}

flatbuffers::Offset<NetProtocol::TouchData>
convert_touch_data(flatbuffers::FlatBufferBuilder &builder,
                   const SceTouchData &data) {
  std::vector<NetProtocol::TouchReport> reports(data.reportNum);
  for (size_t i = 0; i < data.reportNum; i++) {
    NetProtocol::TouchReport report(data.report[i].force, data.report[i].id,
                                    data.report[i].x, data.report[i].y);
    reports[i] = report;
  }

  return NetProtocol::CreateTouchDataDirect(builder, &reports);
}

flatbuffers::FlatBufferBuilder get_ctrl_as_netprotocol() {
  SceCtrlData pad;
  SceMotionSensorState motion_data; // TODO: Needs calibration
  SceTouchData touch_data_front, touch_data_back;

  flatbuffers::FlatBufferBuilder builder(512);

  sceCtrlPeekBufferPositive(0, &pad, 1);
  auto buttons = convert_pad_data(pad);

  sceTouchPeek(SCE_TOUCH_PORT_FRONT, &touch_data_front, 1);
  auto data_front = convert_touch_data(builder, touch_data_front);

  sceTouchPeek(SCE_TOUCH_PORT_BACK, &touch_data_back, 1);
  auto data_back = convert_touch_data(builder, touch_data_back);

  sceMotionGetSensorState(&motion_data, 1);
  NetProtocol::Vector3 accel(motion_data.accelerometer.x,
                             motion_data.accelerometer.y,
                             motion_data.accelerometer.z);
  NetProtocol::Vector3 gyro(motion_data.gyro.x, motion_data.gyro.y,
                            motion_data.gyro.z);
  NetProtocol::MotionData motion(accel, gyro);

  auto content =
      NetProtocol::CreatePad(builder, &buttons, pad.lx, pad.ly, pad.rx, pad.ry,
                             data_front, data_back, &motion, pad.timeStamp);

  auto packet = NetProtocol::CreatePacket(
      builder, NetProtocol::PacketContent::Pad, content.Union());
  builder.FinishSizePrefixed(packet);

  return builder;
}
