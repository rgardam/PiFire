'''
*****************************************
PiFire Bluetooth Inkbird INT-14-BW Module
*****************************************

Probe module for the Inkbird INT-14-BW four-probe wireless BLE thermometer.

The INT-14-BW has 4 wireless probes (each battery-powered, Meater-style) with
two sensors per probe (tip + ambient). The base station aggregates readings
from all four probes and streams them over BLE.

Protocol (reverse-engineered from a live device):
  Service:         0xFF00 (0000ff00-0000-1000-8000-00805f9b34fb)
  Characteristic:  0xFF01 (0000ff01-0000-1000-8000-00805f9b34fb) - read, notify
  Payload:         18 bytes
    bytes 0-1    probe 1 tip temp        uint16 LE, tenths of degC
    bytes 2-3    probe 1 ambient temp    uint16 LE, tenths of degC
    bytes 4-5    probe 2 tip temp
    bytes 6-7    probe 2 ambient temp
    bytes 8-9    probe 3 tip temp
    bytes 10-11  probe 3 ambient temp
    bytes 12-13  probe 4 tip temp
    bytes 14-15  probe 4 ambient temp
    bytes 16-17  status/counter
  0x7FFE sentinel: probe slot is unavailable (flat battery / not paired)

Battery frame on repurposed 0x2A19 (5 bytes):
    byte 0    header, 0x27
    byte 1    counter
    bytes 2-4 three uint8 battery percents (probe->byte mapping unconfirmed)

This module uses bleak (BlueZ DBus) rather than bluepy because bluepy needs
raw HCI socket access and conflicts with the system bluez daemon on
Docker-on-host-network and Raspberry Pi OS Bookworm setups. bleak
cooperates with bluez.

Device config:
    device_info = {
        'device': 'IntUserName',
        'module': 'bt_int14bw',
        'ports': ['BT1_Tip', 'BT1_Amb', 'BT2_Tip', 'BT2_Amb',
                  'BT3_Tip', 'BT3_Amb', 'BT4_Tip', 'BT4_Amb'],
        'config': {
            'hardware_id': 'xx:xx:xx:xx:xx:xx',
            'transient': True,
        }
    }
'''

import asyncio
import logging
import threading
import time

from probes.base import ProbeInterface
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

_TEMP_CHAR_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
_BATT_CHAR_UUID = "00002a19-0000-1000-8000-00805f9b34fb"

_FRAME_LEN = 18
_BATT_FRAME_LEN = 5
_BATT_FRAME_HEADER = 0x27
_NUM_PROBES = 4
_UNPLUGGED_SENTINEL = 0x7FFE
_POLL_INTERVAL_S = 2.0
_RECONNECT_INTERVAL_S = 2.0
_SCAN_TIMEOUT_S = 8.0
_CONNECT_TIMEOUT_S = 20.0
_STALE_DATA_TIMEOUT_S = 20.0

PORT_ORDER = [
    "BT1_Tip", "BT1_Amb",
    "BT2_Tip", "BT2_Amb",
    "BT3_Tip", "BT3_Amb",
    "BT4_Tip", "BT4_Amb",
]


def _parse_frame(data):
    """Parse an 18-byte INT-14-BW temperature frame into 8 Celsius values.

    Returns a list aligned with PORT_ORDER. None means probe unavailable.
    Returns None if the frame length is wrong.
    """
    if data is None or len(data) < _FRAME_LEN:
        return None
    out = []
    for i in range(_NUM_PROBES * 2):
        raw = int.from_bytes(data[i * 2:(i * 2) + 2], "little")
        if raw == _UNPLUGGED_SENTINEL:
            out.append(None)
        else:
            out.append(raw / 10.0)
    return out


def _parse_battery_frame(data):
    """Parse a 5-byte battery frame (repurposed 0x2A19 characteristic).

    Returns (counter, [batt1, batt2, batt3]) or None if unrecognized.
    Only 3 battery values are in the frame even though the device has 4
    probes — the probe->byte mapping is not yet confirmed.
    """
    if data is None or len(data) < _BATT_FRAME_LEN:
        return None
    if data[0] != _BATT_FRAME_HEADER:
        return None
    return data[1], [data[2], data[3], data[4]]


class Int14bwDevice:
    """BLE client for the INT-14-BW running its own asyncio loop in a thread."""

    def __init__(self, units, hardware_id=None, transient=True):
        self.logger = logging.getLogger("control")
        self.units = units
        self.transient = transient
        self.hardware_id = (hardware_id or None)

        self.device_setup = False
        self._values_C = [None] * (_NUM_PROBES * 2)
        self._probe_batteries = []

        self.status = {
            "battery_percentage": None,
            "battery_charging": False,
            "connected": False,
            "hardware_id": self.hardware_id,
            "probe_batteries": [],
        }

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()

    def _thread_main(self):
        try:
            asyncio.run(self._run())
        except Exception as e:
            self.logger.debug(f"(int14bw) async thread crashed: {e}")

    async def _run(self):
        while not self._stop.is_set():
            try:
                if self.hardware_id is None:
                    await self._scan_for_device()
                    if self.hardware_id is None:
                        await asyncio.sleep(_RECONNECT_INTERVAL_S)
                        continue
                await self._connect_and_stream()
            except BleakError as e:
                self.logger.debug(f"(int14bw) bleak error: {e}")
            except Exception as e:
                self.logger.debug(f"(int14bw) unexpected error: {e}")
            finally:
                self.device_setup = False
                self.status["connected"] = False
            await asyncio.sleep(_RECONNECT_INTERVAL_S)

    async def _scan_for_device(self):
        self.logger.info("(int14bw) scanning for device...")
        devices = await BleakScanner.discover(
            timeout=_SCAN_TIMEOUT_S, return_adv=True
        )
        best_addr = None
        best_rssi = -999
        for addr, (_dev, adv) in devices.items():
            name = adv.local_name or ""
            if "INT-14" in name.upper():
                rssi = adv.rssi if adv.rssi is not None else -999
                if rssi > best_rssi:
                    best_addr = addr
                    best_rssi = rssi
        if best_addr:
            self.hardware_id = best_addr
            self.status["hardware_id"] = best_addr
            self.logger.info(
                f"(int14bw) discovered device at {best_addr} rssi={best_rssi}"
            )

    async def _connect_and_stream(self):
        self.logger.info(f"(int14bw) locating {self.hardware_id} via bluez...")
        target = await BleakScanner.find_device_by_address(
            self.hardware_id, timeout=_SCAN_TIMEOUT_S
        )
        if target is None:
            self.logger.debug(
                f"(int14bw) {self.hardware_id} not seen by bluez in "
                f"{_SCAN_TIMEOUT_S}s — will retry"
            )
            return

        disconnected = asyncio.Event()

        def on_disconnect(_client):
            disconnected.set()

        self.logger.info(f"(int14bw) connecting to {self.hardware_id}...")
        async with BleakClient(
            target,
            timeout=_CONNECT_TIMEOUT_S,
            disconnected_callback=on_disconnect,
        ) as client:
            self.device_setup = True
            self.status["connected"] = True
            self.logger.info(f"(int14bw) connected to {self.hardware_id}")

            def on_temp(_char, data):
                self._handle_temp_frame(bytes(data))

            def on_batt(_char, data):
                self._handle_battery_frame(bytes(data))

            try:
                await client.start_notify(_TEMP_CHAR_UUID, on_temp)
            except Exception as e:
                self.logger.debug(f"(int14bw) temp subscribe failed: {e}")
            try:
                await client.start_notify(_BATT_CHAR_UUID, on_batt)
            except Exception as e:
                self.logger.debug(f"(int14bw) battery subscribe failed: {e}")

            try:
                self._handle_temp_frame(bytes(await client.read_gatt_char(_TEMP_CHAR_UUID)))
            except Exception:
                pass
            try:
                self._handle_battery_frame(bytes(await client.read_gatt_char(_BATT_CHAR_UUID)))
            except Exception:
                pass

            batt_counter = 0
            while (client.is_connected
                   and not self._stop.is_set()
                   and not disconnected.is_set()):
                try:
                    await asyncio.wait_for(
                        disconnected.wait(), timeout=_POLL_INTERVAL_S
                    )
                    break
                except asyncio.TimeoutError:
                    pass
                try:
                    temp = await client.read_gatt_char(_TEMP_CHAR_UUID)
                    self._handle_temp_frame(bytes(temp))
                except Exception as e:
                    self.logger.debug(f"(int14bw) temp poll error: {e}")
                    break
                # Poll battery less often — it rarely changes and the read is
                # slow on this device.
                batt_counter += 1
                if batt_counter % 5 == 0:
                    try:
                        batt = await client.read_gatt_char(_BATT_CHAR_UUID)
                        self._handle_battery_frame(bytes(batt))
                    except Exception as e:
                        self.logger.debug(f"(int14bw) battery poll error: {e}")

    def _handle_temp_frame(self, data):
        values = _parse_frame(data)
        if values is None:
            return
        self._values_C = values

    def _handle_battery_frame(self, data):
        parsed = _parse_battery_frame(data)
        if parsed is None:
            return
        counter, batteries = parsed
        self._probe_batteries = batteries
        non_zero = [b for b in batteries if b > 0]
        self.status["probe_batteries"] = list(batteries)
        self.status["battery_percentage"] = min(non_zero) if non_zero else None
        self.status["battery_charging"] = False
        self.logger.info(
            f"(int14bw) battery frame counter={counter} raw_batteries={batteries}"
        )

    def get_port_values_C(self):
        return list(self._values_C)

    def get_status(self):
        self.status["connected"] = self.device_setup
        self.status["hardware_id"] = self.hardware_id
        return self.status


class ReadProbes(ProbeInterface):

    def __init__(self, probe_info, device_info, units):
        self.hardware_id = device_info["config"].get("hardware_id", None) or None
        super().__init__(probe_info, device_info, units)

    def _init_device(self):
        self.time_delay = 0
        self.device = Int14bwDevice(
            self.units,
            hardware_id=self.hardware_id,
            transient=self.transient,
        )

    def read_all_ports(self, output_data):
        values_C = self.device.get_port_values_C()

        for port in self.port_map:
            try:
                index = PORT_ORDER.index(port)
            except ValueError:
                continue
            value_c = values_C[index] if index < len(values_C) else None
            if value_c is None:
                port_value = None
            elif self.units == "C":
                port_value = value_c
            else:
                port_value = self._to_fahrenheit(value_c)

            self.output_data["tr"][self.port_map[port]] = 0

            if port == self.primary_port:
                self.output_data["primary"][self.port_map[port]] = port_value
            elif port in self.food_ports:
                self.output_data["food"][self.port_map[port]] = port_value
            elif port in self.aux_ports:
                self.output_data["aux"][self.port_map[port]] = port_value

        return self.output_data
