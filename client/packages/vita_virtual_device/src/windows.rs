use rstar::{primitives::Rectangle, RTree, AABB};
use serde::{Deserialize, Serialize};
use vigem_client::{
    Client, DS4Buttons, DS4ReportExBuilder, DS4TouchPoint, DS4TouchReport, DpadDirection,
    DualShock4Wired, TargetId,
};

use std::{ffi::OsString, time::Duration};

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

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum TouchAction {
    Dpad(u16),
    Button(u16),
}

/// Point in 2D space (x, y).
#[derive(Clone, Debug, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct Point(pub i32, pub i32);

impl Point {
    #[inline]
    pub fn x(&self) -> i32 {
        self.0
    }

    #[inline]
    pub fn y(&self) -> i32 {
        self.1
    }
}

impl rstar::Point for Point {
    type Scalar = i32;

    const DIMENSIONS: usize = 2;

    #[inline]
    fn generate(mut generator: impl FnMut(usize) -> Self::Scalar) -> Self {
        Point(generator(0), generator(1))
    }

    #[inline]
    fn nth(&self, index: usize) -> Self::Scalar {
        match index {
            0 => self.0,
            1 => self.1,
            _ => unreachable!(),
        }
    }

    #[inline]
    fn nth_mut(&mut self, index: usize) -> &mut Self::Scalar {
        match index {
            0 => &mut self.0,
            1 => &mut self.1,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TouchZone {
    rect: Rectangle<Point>,
    /// The emulated action to perform when the touch zone is touched.
    action: Option<TouchAction>,
}

impl TouchZone {
    #[inline]
    pub fn new(rect: (Point, Point), action: Option<TouchAction>) -> Self {
        TouchZone {
            rect: AABB::from_corners(rect.0, rect.1).into(),
            action,
        }
    }
}

impl rstar::RTreeObject for TouchZone {
    type Envelope = AABB<Point>;

    #[inline]
    fn envelope(&self) -> Self::Envelope {
        self.rect.envelope()
    }
}

impl rstar::PointDistance for TouchZone {
    #[inline]
    fn distance_2(&self, point: &Point) -> i32 {
        self.rect.distance_2(point)
    }

    #[inline]
    fn contains_point(&self, point: &<Self::Envelope as rstar::Envelope>::Point) -> bool {
        self.rect.contains_point(point)
    }

    #[inline]
    fn distance_2_if_less_or_equal(&self, point: &Point, max_distance_2: i32) -> Option<i32> {
        self.rect.distance_2_if_less_or_equal(point, max_distance_2)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[doc(hidden)]
pub enum TouchConfig {
    Zones(RTree<TouchZone>),
    Touchpad,
}

impl TouchConfig {
    pub fn zones<I: IntoIterator<Item = TouchZone>>(it: I) -> Self {
        TouchConfig::Zones(RTree::bulk_load(it.into_iter().collect()))
    }

    #[inline]
    pub fn touchpad() -> Self {
        TouchConfig::Touchpad
    }
}

#[derive(Clone, Debug, Copy, Deserialize, Serialize)]
pub enum TriggerConfig {
    Shoulder,
    Trigger,
}

impl Default for TriggerConfig {
    #[inline]
    fn default() -> Self {
        TriggerConfig::Shoulder
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
pub struct Config {
    pub front_touch_config: Option<TouchConfig>,
    pub rear_touch_config: Option<TouchConfig>,
    pub trigger_config: TriggerConfig,
}

// Touch coordinates are in the range [0, 1919] x [108, 887] for the back touchpad
// and [0, 1919] x [0, 1087] for the front touchpad
const FRONT_TOUCHPAD_RECT: (Point, Point) = (Point(0, 0), Point(1920, 1087));
const BACK_TOUCHPAD_RECT: (Point, Point) = (Point(0, 108), Point(1920, 887));

impl Config {
    #[inline]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    #[inline]
    pub fn back_l2_r2_front_touchpad() -> Self {
        Config {
            rear_touch_config: Some(TouchConfig::zones([
                TouchZone::new(
                    (
                        BACK_TOUCHPAD_RECT.0,
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.1.y()),
                    ),
                    Some(TouchAction::Button(DS4Buttons::TRIGGER_LEFT)),
                ),
                TouchZone::new(
                    (
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.0.y()),
                        BACK_TOUCHPAD_RECT.1,
                    ),
                    Some(TouchAction::Button(DS4Buttons::TRIGGER_RIGHT)),
                ),
            ])),
            front_touch_config: Some(TouchConfig::Touchpad),
            trigger_config: TriggerConfig::Shoulder,
        }
    }

    #[inline]
    pub fn back_l2_l3_r2_r3_front_touchpad() -> Self {
        Config {
            rear_touch_config: Some(TouchConfig::zones([
                TouchZone::new(
                    (
                        BACK_TOUCHPAD_RECT.0,
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.1.y() / 2),
                    ),
                    Some(TouchAction::Button(DS4Buttons::TRIGGER_LEFT)),
                ),
                TouchZone::new(
                    (
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.0.y()),
                        Point(BACK_TOUCHPAD_RECT.1.x(), BACK_TOUCHPAD_RECT.1.y() / 2),
                    ),
                    Some(TouchAction::Button(DS4Buttons::TRIGGER_RIGHT)),
                ),
                TouchZone::new(
                    (
                        Point(BACK_TOUCHPAD_RECT.0.x(), BACK_TOUCHPAD_RECT.1.y() / 2),
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.1.y()),
                    ),
                    Some(TouchAction::Button(DS4Buttons::THUMB_LEFT)),
                ),
                TouchZone::new(
                    (
                        Point(BACK_TOUCHPAD_RECT.1.x() / 2, BACK_TOUCHPAD_RECT.1.y() / 2),
                        BACK_TOUCHPAD_RECT.1,
                    ),
                    Some(TouchAction::Button(DS4Buttons::THUMB_RIGHT)),
                ),
            ])),
            front_touch_config: Some(TouchConfig::Touchpad),
            trigger_config: TriggerConfig::Shoulder,
        }
    }
}

impl Default for Config {
    #[inline]
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
            config: Config::back_l2_l3_r2_r3_front_touchpad(),
        })
    }
}

impl VitaVirtualDevice<&ConfigBuilder> for VitaDevice {
    type Config = Config;

    fn identifiers(&self) -> Option<&[OsString]> {
        None
    }

    #[inline]
    fn get_config(&self) -> &Self::Config {
        &self.config
    }

    #[inline]
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
                if let Some(zone) = zones.locate_at_point(&Point(touch.x.into(), touch.y.into())) {
                    if let Some(action) = zone.action {
                        match action {
                            TouchAction::Button(button) => buttons |= button,
                            _ => {}
                        }
                    }
                }
            }
        }

        for touch in &report.back_touch.reports {
            if let Some(TouchConfig::Zones(zones)) = &self.config.rear_touch_config {
                if let Some(zone) = zones.locate_at_point(&Point(touch.x.into(), touch.y.into())) {
                    if let Some(action) = zone.action {
                        match action {
                            TouchAction::Button(button) => buttons |= button,
                            _ => {}
                        }
                    }
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
