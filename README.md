# ArduPilot SITL: GPS Spoofing & Sensor-Manipulation Detection

A hands-on project exploring drone sensor security using ArduPilot's Software-In-The-Loop
(SITL) simulator. The project covers three stages: getting a simulated drone flying, injecting
a GPS spoofing attack directly into the simulator's sensor model, and building two lightweight
intrusion detectors to catch it.

> Educational project built on ArduPilot's open-source SITL simulator. All attacks were run
> against a simulated vehicle only — no real hardware or GNSS signals were involved.

## Overview

- **Stage 1 — Setup & baseline flight**: Installed ArduPilot SITL (ArduCopter), flew manual and
  pre-planned missions, and observed how wind and sensor failures (compass, GPS) affect flight
  behavior and ArduPilot's built-in failsafes.
- **Stage 2 — Sensor pipeline & GPS spoofing**: Traced how sensor data flows from driver to EKF
  to flight controller, then patched the simulator's synthetic GPS generator to inject both a
  simple static offset and a precisely "controlled" spoof that lures the drone to an attacker-chosen
  location while it thinks it's still following its mission.
- **Stage 3 — Detection**: Built two intrusion detectors from scratch and compiled them into
  ArduCopter: a stateless speed-plausibility check, and a cross-sensor (GPS altitude vs. barometer
  altitude) invariant check. Also demonstrated a "boiling frog" style slow-drift attack that evades
  the stateless detector.

## Stage 1: Environment & Baseline Behavior

ArduPilot's SITL simulator was set up and launched with:

```bash
python3 ./ardupilot/Tools/autotest/sim_vehicle.py sim_vehicle.py -v ArduCopter --console --map
```

A mission was drawn directly on the map (waypoints at 100 m altitude), saved, reloaded, armed,
and flown in `AUTO` mode.

**Wind:** Setting `SIM_WIND_SPD 30` produced visible drift off the planned path, with larger
deviations before the controller re-stabilized.

**Sensor failures:**
- Disabling the compass (`COMPASS_ENABLE 0`) mid-flight had no immediate effect, but blocked
  arming entirely after a reboot until it was re-enabled — the pre-arm checks require it.
- Disabling GPS (`SIM_GPS1_ENABLE 0`) mid-flight caused the EKF to lose its position estimate,
  and ArduCopter automatically failsafed into `LAND` mode and disarmed — a good first look at
  ArduPilot's built-in protection against sensor loss.

Flight logs (`.BIN`) were reviewed in ArduPilot's [UAV Log Viewer](https://plot.ardupilot.org/)
to confirm trajectory, mode changes, and failsafe triggers.

## Stage 2: Sensor Pipeline & GPS Spoofing

### How sensor data reaches the controller

**IMU (MPU6000):** Communicates over SPI. The driver
(`libraries/AP_InertialSensor/AP_InertialSensor_Invensense.cpp`) initializes the chip, reads raw
accelerometer/gyro registers, converts them into `Vector3f` values, and forwards them via
`_notify_new_accel_raw_sample()` / `_notify_new_gyro_raw_sample()` into the EKF.

**GPS:** On real hardware, GPS modules stream NMEA/UBX-style packets over UART. ArduPilot's
`libraries/AP_GPS/` directory holds backend drivers for different receivers (u-blox, SiRF,
Septentrio, and a SITL-specific backend), each responsible for parsing protocol messages and
extracting position, velocity, heading, fix status, and satellite count.

**How SITL fakes GPS:** Because there's no physical receiver in simulation, `libraries/SITL/SIM_GPS.cpp`
reads the simulator's ground-truth position and packages it into synthetic UBX packets, which
are then parsed by the same `AP_GPS_UBLOX` backend used on real hardware. This makes `SIM_GPS.cpp`
the natural place to inject a spoofing attack — any tampering here is indistinguishable, from the
autopilot's point of view, from a real over-the-air spoofing attack.

### Attack 1: Static offset spoof

A constant lateral offset was added to the simulated latitude/longitude inside `SIM_GPS.cpp`,
gated to activate 25 seconds after boot (letting the EKF converge and takeoff complete first):

```cpp
const uint32_t SPOOF_START_MS = 25000;
const double SPOOF_OFFSET_LAT = 0.01;  // ~1 km north
const double SPOOF_OFFSET_LON = 0.01;  // ~900 m east at this latitude
static bool spoof_announced = false;

if (now_ms > SPOOF_START_MS) {
    d.latitude  += SPOOF_OFFSET_LAT;
    d.longitude += SPOOF_OFFSET_LON;
    if (!spoof_announced) {
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "GPS SPOOF ACTIVE");
        spoof_announced = true;
    }
}
```

Comparing `GPS_RAW_INT` (what the autopilot believes) against `SIMSTATE` (ground truth) confirmed
a constant ~0.01° offset in both axes after activation — the drone's on-map marker shifted about
1 km from its real position, and the flight controller trusted it completely.

### Attack 2: Controlled spoof to an attacker-chosen target

The static offset was then generalized so the *reported* GPS position converges on an
attacker-chosen real-world coordinate, even while the mission logic still thinks it's flying
toward its original waypoint:

```
offset = attacker_target − mission_waypoint
fake_position = real_position − offset
```

```cpp
const double ATTACK_LAT = -35.355540, ATTACK_LON = 149.165085; double ATTACK_ALT = 100.0f;
const double WP_LAT     = -35.363262, WP_LON     = 149.159778; float  WP_ALT     = 100.0f;

const double offset_lat = ATTACK_LAT - WP_LAT;
const double offset_lon = ATTACK_LON - WP_LON;
const float  offset_alt = ATTACK_ALT - WP_ALT;

if (now_ms > SPOOF_START_MS) {
    d.latitude  -= offset_lat;
    d.longitude -= offset_lon;
    d.altitude  -= offset_alt;
}
```

Result: the real (simulated) drone position converged on the attacker's chosen coordinate with
roughly 0.4 m latitude / 0.3 m longitude error, with no discontinuity ever visible to the EKF —
because the offset was constant, every spoofed reading stayed internally consistent with the last.

## Stage 3: Detection

### Detector 1 — Stateless speed-plausibility check

**Idea:** A multirotor has a physically bounded top speed. If two consecutive GPS fixes imply a
speed no real drone could achieve, something is lying.

A short baseline flight showed normal GPS-reported ground speed sitting at 10 m/s ± 0.03 m/s.
A threshold of **25 m/s** was chosen — comfortably above normal noise, low enough to catch a
meaningful jump.

`ArduCopter/gps_ids.cpp`:

```cpp
#include "Copter.h"

void Copter::ids_stateless_check()
{
    static uint32_t previous_time_ms = 0;
    static Location previous_position;
    static bool have_previous = false;

    const AP_GPS &gps_ref = AP::gps();
    if (gps_ref.status() < AP_GPS_FixType::FIX_3D) {
        have_previous = false;
        return;
    }

    const uint32_t current_time_ms = AP_HAL::millis();
    const Location current_position = gps_ref.location();

    if (!have_previous) {
        previous_time_ms = current_time_ms;
        previous_position = current_position;
        have_previous = true;
        return;
    }

    const float seconds_passed = (current_time_ms - previous_time_ms) * 0.001f;
    if (seconds_passed <= 0.0f) return;

    const float metres_moved  = current_position.get_distance(previous_position);
    const float implied_speed = metres_moved / seconds_passed; // m/s

    const float SPEED_LIMIT = 25.0f;
    if (implied_speed > SPEED_LIMIT) {
        GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                      "IDS: GPS jump %.1f m/s > %.1f, failsafe!",
                      (double)implied_speed, (double)SPEED_LIMIT);
        set_mode(Mode::Number::LAND, ModeReason::GPS_GLITCH);
    }

    previous_time_ms = current_time_ms;
    previous_position = current_position;
}
```

Wiring it in: declared in `ArduCopter/Copter.h`, and called from the existing
`ten_hz_logging_loop()` in `ArduCopter/Copter.cpp` (registering it as a new `SCHED_TASK` triggered
an internal scheduler-timing error, so it was folded into an existing 10 Hz loop instead).

**Result — 1 km instant jump:** Detected immediately; the detector commanded `LAND` and
ArduPilot's own EKF lane-switch protection fired independently at the same moment.

**Evading it — the "boiling frog" attack:** Since the detector only ever compares two
*consecutive* readings, a slow ramp never trips it. The offset was changed to grow linearly from
60 s to 210 s after boot, reaching the same ~1 km displacement — an average drift of ~7 m/s,
safely under the 25 m/s threshold:

```cpp
const uint32_t SPOOF_START_MS    = 60000;   // start lying at 60 s
const uint32_t RAMP_DURATION_MS  = 150000;  // reach full offset over 150 s
const double   MAX_OFFSET        = 0.01;    // final displacement: ~1 km

double frac = (double)(now_ms - SPOOF_START_MS) / RAMP_DURATION_MS;
if (frac > 1.0) frac = 1.0;
latitude  += MAX_OFFSET * frac;
longitude += MAX_OFFSET * frac;
```

This version reached the full 1 km displacement without ever triggering an alarm — a clean
demonstration of why single-sample bad-data detectors are insufficient on their own.

### Detector 2 — Invariant-based cross-sensor check

**Idea:** GPS altitude and barometric altitude measure the same physical quantity through
completely unrelated mechanisms (satellite geometry vs. air pressure). They won't read identical
values — each has its own reference zero — but the *gap* between them should stay roughly
constant throughout a flight. A sudden shift in that gap means one sensor disagrees with the
other.

A short baseline flight showed the GPS/baro altitude gap drifting by no more than ±0.6 m under
normal noise. A threshold of **10 m** (well over 10× the noise floor) was chosen.

```cpp
void Copter::ids_invariant_check()
{
    if (!hal.util->get_soft_armed()) return;

    const AP_GPS &gps_ref = AP::gps();
    static bool  baseline_learned = false;
    static float baseline_gap = 0.0f;

    if (gps_ref.status() < AP_GPS_FixType::FIX_3D) {
        baseline_learned = false;
        return;
    }

    const float ids_gps_alt_m  = gps_ref.location().alt * 0.01f;  // cm -> m
    const float ids_baro_alt_m = AP::baro().get_altitude_AMSL();
    const float gap = ids_gps_alt_m - ids_baro_alt_m;

    if (!baseline_learned) {
        baseline_gap = gap;
        baseline_learned = true;
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "IDS inv: baseline gap %.1f m learned", (double)baseline_gap);
        return;
    }

    const float drift = fabsf(gap - baseline_gap);
    const float DRIFT_LIMIT = 10.0f; // metres

    if (drift > DRIFT_LIMIT) {
        GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                      "IDS: GPS/baro alt mismatch %.1f m > %.1f, failsafe!",
                      (double)drift, (double)DRIFT_LIMIT);
        set_mode(Mode::Number::LAND, ModeReason::GPS_GLITCH);
    }
}
```

Called from the same `ten_hz_logging_loop()`, alongside the stateless check.

**Test attack:** A GPS altitude offset of +30 m was injected 60 seconds after takeoff (after the
baseline gap had been learned). The barometer, unaffected, held steady — so the gap jumped from
~0 m to 14–30 m, well past the 10 m threshold. The detector fired and commanded `LAND`.

Crucially, this detector catches an attack the *speed* detector would miss entirely: a slow
altitude drift produces no unrealistic implied ground speed at all, since it only affects the
vertical axis. Cross-sensor correlation catches classes of manipulation that single-sensor
plausibility checks structurally can't.

## Key Takeaways

- Any point in the sensor pipeline — physical signal, driver, bus, or software model — is a
  potential injection point, and in simulation `SIM_GPS.cpp` stands in for all of them at once.
- A single, constant spoofing offset is invisible to the EKF because every reading stays
  internally consistent with the last.
- Stateless "bad data" detectors are effective against sudden jumps but are trivially evaded by
  a sufficiently slow, gradual attack ("boiling frog").
- Cross-sensor invariants (GPS vs. barometer altitude) catch classes of attack that single-sensor
  thresholds miss, since the two sensors are physically decorrelated and manipulating one alone
  breaks their normal relationship.
- Real defenses combine both approaches — plus attention to the *start/stop* transients of an
  attack, which is where slow-drift attacks are most likely to still leak a detectable signature.

## Repository Structure

```
.
├── README.md
├── code/
│   ├── gps_ids.cpp              # stateless + invariant detectors (ArduCopter/)
│   ├── SIM_GPS_static_spoof.patch
│   ├── SIM_GPS_controlled_spoof.patch
│   ├── SIM_GPS_ramp_spoof.patch
│   └── SIM_GPS_alt_spoof.patch
├── logs/
│   └── *.BIN                    # flight logs for each attack/detection scenario
└── figures/
    └── *.png                    # GPS vs SIMSTATE plots, map screenshots, console captures
```

## Tooling

- [ArduPilot](https://ardupilot.org/) SITL (ArduCopter)
- MAVProxy console + map GUI
- [UAV Log Viewer](https://plot.ardupilot.org/) for `.BIN` log analysis

---
*Educational project — not intended as production-grade attack or defense tooling.*
