use rstar::{primitives::Rectangle, RTree, AABB};
use std::{ffi::OsString, time::Duration};
use vigem_client::{
    Client, DS4Buttons, DS4ReportExBuilder, DS4TouchPoint, DS4TouchReport, DpadDirection,
    DualShock4Wired, TargetId,
};

use crate::VitaVirtualDevice;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to connect to the client")]
    ConnectionFailed(#[source] vigem_client::Error),
    #[error("Failed to plugin the target")]
    PluginTargetFailed(#[source] vigem_client::Error),
    #[error("Sending report failed")]
    SendReportFailed(#[source] vigem_client::Error),
}

// TODO: use u16 instead of i32
#[derive(Clone, Debug)]
pub struct TouchZone {
    rect: Rectangle<(i32, i32)>,
    /// The button to emulate when the zone is touched
    button: u16,
}

impl rstar::RTreeObject for TouchZone {
    type Envelope = AABB<(i32, i32)>;

    fn envelope(&self) -> Self::Envelope {
        self.rect.envelope()
    }
}

impl rstar::PointDistance for TouchZone {
    fn distance_2(&self, point: &(i32, i32)) -> i32 {
        self.rect.distance_2(point)
    }

    fn contains_point(&self, point: &<Self::Envelope as rstar::Envelope>::Point) -> bool {
        self.rect.contains_point(point)
    }

    fn distance_2_if_less_or_equal(&self, point: &(i32, i32), max_distance_2: i32) -> Option<i32> {
        self.rect.distance_2_if_less_or_equal(point, max_distance_2)
    }
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub enum TouchConfig {
    Zones(RTree<TouchZone>),
    Touchpad,
}

#[derive(Clone, Debug, Copy)]
pub enum TriggerConfig {
    Shoulder,
    Trigger,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        TriggerConfig::Shoulder
    }
}

#[derive(Clone, Debug, derive_builder::Builder)]
pub struct Config {
    front_touch_config: Option<TouchConfig>,
    rear_touch_config: Option<TouchConfig>,
    trigger_config: TriggerConfig,
}

// Touch coordinates are in the range [0, 1919] x [108, 887] for the back touchpad
// and [0, 1919] x [0, 1087] for the front touchpad
const FRONT_TOUCHPAD_RECT: ((i32, i32), (i32, i32)) = ((0, 0), (1920, 1087));
const BACK_TOUCHPAD_RECT: ((i32, i32), (i32, i32)) = ((0, 108), (1920, 887));

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    pub fn back_l2_r2_front_touchpad() -> Self {
        Config {
            rear_touch_config: Some(TouchConfig::Zones(RTree::bulk_load(vec![
                TouchZone {
                    rect: Rectangle::from_corners(
                        BACK_TOUCHPAD_RECT.0,
                        ((BACK_TOUCHPAD_RECT.1).0 / 2, (BACK_TOUCHPAD_RECT.1).1),
                    ),
                    button: DS4Buttons::TRIGGER_LEFT,
                },
                TouchZone {
                    rect: Rectangle::from_corners(
                        ((BACK_TOUCHPAD_RECT.1).0 / 2, (BACK_TOUCHPAD_RECT.0).0),
                        BACK_TOUCHPAD_RECT.1,
                    ),
                    button: DS4Buttons::TRIGGER_RIGHT,
                },
            ]))),
            front_touch_config: Some(TouchConfig::Zones(RTree::bulk_load(vec![
                TouchZone {
                    rect: Rectangle::from_corners(
                        FRONT_TOUCHPAD_RECT.0,
                        ((FRONT_TOUCHPAD_RECT.1).0 / 2, (FRONT_TOUCHPAD_RECT.1).1),
                    ),
                    button: DS4Buttons::THUMB_LEFT,
                },
                TouchZone {
                    rect: Rectangle::from_corners(
                        ((FRONT_TOUCHPAD_RECT.1).0 / 2, (FRONT_TOUCHPAD_RECT.0).0),
                        FRONT_TOUCHPAD_RECT.1,
                    ),
                    button: DS4Buttons::THUMB_RIGHT,
                },
            ]))),
            trigger_config: TriggerConfig::Shoulder,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            front_touch_config: Some(TouchConfig::Touchpad),
            rear_touch_config: None,
            trigger_config: TriggerConfig::default(),
        }
    }
}

pub struct VitaDevice {
    ds4_target: DualShock4Wired<Client>,
    config: Config,
}

impl VitaDevice {
    pub fn create() -> crate::Result<Self> {
        let client = Client::connect().map_err(Error::ConnectionFailed)?;
        let mut ds4_target = DualShock4Wired::new(client, TargetId::DUALSHOCK4_WIRED);

        ds4_target.plugin().map_err(Error::PluginTargetFailed)?;
        ds4_target.wait_ready().map_err(Error::PluginTargetFailed)?;
        // Wait for the device to be ready, because the ioctl doesn't seem to work
        std::thread::sleep(Duration::from_millis(100));

        Ok(VitaDevice {
            ds4_target,
            config: Config::back_l2_r2_front_touchpad(),
        })
    }
}

impl VitaVirtualDevice<&ConfigBuilder> for VitaDevice {
    type Config = Config;

    fn identifiers(&self) -> Option<&[OsString]> {
        None
    }

    fn set_config(&mut self, config: &ConfigBuilder) -> crate::Result<()> {
        if let Some(front_touch_config) = &config.front_touch_config {
            self.config.front_touch_config = front_touch_config.clone();
        }

        if let Some(rear_touch_config) = &config.rear_touch_config {
            self.config.rear_touch_config = rear_touch_config.clone();
        }

        if let Some(trigger_config) = config.trigger_config {
            self.config.trigger_config = trigger_config;
        }

        Ok(())
    }

    fn send_report(&mut self, report: vita_reports::MainReport) -> crate::Result<()> {
        let dpad = match (
            report.buttons.down,
            report.buttons.left,
            report.buttons.up,
            report.buttons.right,
        ) {
            (true, false, false, false) => DpadDirection::South,
            (true, true, false, false) => DpadDirection::SouthWest,
            (false, true, false, false) => DpadDirection::West,
            (false, true, true, false) => DpadDirection::NorthWest,
            (false, false, true, false) => DpadDirection::North,
            (false, false, true, true) => DpadDirection::NorthEast,
            (false, false, false, true) => DpadDirection::East,
            (true, false, false, true) => DpadDirection::SouthEast,
            _ => DpadDirection::None,
        };

        let mut buttons = DS4Buttons::new()
            .circle(report.buttons.circle)
            .square(report.buttons.square)
            .cross(report.buttons.cross)
            .triangle(report.buttons.triangle)
            .options(report.buttons.start)
            .share(report.buttons.select)
            .dpad(dpad);

        for touch in &report.front_touch.reports {
            if let Some(TouchConfig::Zones(zones)) = &self.config.front_touch_config {
                if let Some(zone) = zones.locate_at_point(&(touch.x.into(), touch.y.into())) {
                    buttons |= zone.button;
                }
            }
        }

        for touch in &report.back_touch.reports {
            if let Some(TouchConfig::Zones(zones)) = &self.config.rear_touch_config {
                if let Some(zone) = zones.locate_at_point(&(touch.x.into(), touch.y.into())) {
                    buttons |= zone.button;
                }
            }
        }

        match self.config.trigger_config {
            TriggerConfig::Shoulder => {
                if report.buttons.lt {
                    buttons |= DS4Buttons::SHOULDER_LEFT;
                }
                if report.buttons.rt {
                    buttons |= DS4Buttons::SHOULDER_RIGHT;
                }
            }
            TriggerConfig::Trigger => {
                if report.buttons.lt {
                    buttons |= DS4Buttons::TRIGGER_LEFT;
                }
                if report.buttons.rt {
                    buttons |= DS4Buttons::TRIGGER_RIGHT;
                }
            }
        }

        let touchpad = if let Some(TouchConfig::Touchpad) = self.config.front_touch_config {
            let mut points = report
                .front_touch
                .reports
                .iter()
                .rev()
                .take(2)
                // Convert the coordinates to the range for the dualshock 4 touchpad (1920x942) from the vita touchpad (1920x1087)
                .map(|report| {
                    DS4TouchPoint::new(report.x as u16, (report.y * (942 / 1087)) as u16)
                });
            let report = DS4TouchReport::new(0, points.next(), points.next());
            Some(report)
        } else if let Some(TouchConfig::Touchpad) = self.config.rear_touch_config {
            let mut points = report
                .back_touch
                .reports
                .iter()
                .rev()
                .take(2)
                // Convert the coordinates to the range for the dualshock 4 touchpad (1920x942) from the vita rear touchpad (1920x887)
                .map(|report| {
                    DS4TouchPoint::new(report.x as u16, (report.y * (942 / (887 - 108))) as u16)
                });
            let report = DS4TouchReport::new(0, points.next(), points.next());
            Some(report)
        } else {
            None
        };

        let report = DS4ReportExBuilder::new()
            .thumb_lx(report.lx)
            .thumb_ly(report.ly)
            .thumb_rx(report.rx)
            .thumb_ry(report.ry)
            .buttons(buttons)
            .touch_reports(touchpad, None, None)
            .build();

        self.ds4_target
            .update_ex(&report)
            .map_err(Error::SendReportFailed)?;

        Ok(())
    }
}
