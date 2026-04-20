#!/usr/bin/env python3
"""Inkbird INT-14-BW BLE probe using bleak (bluez DBus).

Unlike the bluepy-based tool, this one cooperates with the host's bluez
daemon so it works alongside system Bluetooth.

Usage:
  python3 bt_int14bw_probe_bleak.py scan
  python3 bt_int14bw_probe_bleak.py listen AA:BB:CC:DD:EE:FF \
      --duration 120 --log bt_int14bw_trace.log
"""
import argparse
import asyncio
import signal
import sys
import time
from typing import Dict, Optional

from bleak import BleakClient, BleakScanner

IBBQ_CREDENTIALS = bytes.fromhex("21 07 06 05 04 03 02 01 b8 22 00 00 00 00 00".replace(" ", ""))
IBBQ_REALTIME_ON = bytes.fromhex("0B01000000 00".replace(" ", ""))
IBBQ_UNITS_C = bytes.fromhex("020000000000")
IBBQ_UNITS_F = bytes.fromhex("020100000000")
IBBQ_BATTERY = bytes.fromhex("082400000000")

PLAUSIBLE_TEMP_C_MIN = -20.0
PLAUSIBLE_TEMP_C_MAX = 300.0
UNPLUGGED_MARKERS = {0xFFFF, 0xFFF6}
NAME_HINTS = ("INT-14", "INKBIRD", "IBBQ", "XBBQ")


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class Tee:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "a", buffering=1)
        self.f.write(f"\n=== session start {ts()} ===\n")

    def write(self, msg):
        line = f"{ts()} {msg}"
        print(line, flush=True)
        try:
            self.f.write(line + "\n")
        except Exception:
            pass

    def close(self):
        try:
            self.f.write(f"=== session end {ts()} ===\n")
            self.f.close()
        except Exception:
            pass


def heuristic_temps_c(data: bytes, num_probes: int):
    if len(data) < 2 * num_probes:
        return None, 0.0
    temps = []
    plausible = 0
    for i in range(num_probes):
        raw = int.from_bytes(data[i * 2:(i * 2) + 2], "little")
        if raw in UNPLUGGED_MARKERS:
            temps.append(None)
            continue
        c = raw / 10.0
        temps.append(c)
        if PLAUSIBLE_TEMP_C_MIN <= c <= PLAUSIBLE_TEMP_C_MAX:
            plausible += 1
    return temps, plausible / num_probes


def fmt_temps(temps):
    return " | ".join(
        "unplugged" if t is None else f"{t:6.1f}C ({t*9/5+32:5.1f}F)"
        for t in temps
    )


async def cmd_scan(args):
    print(f"scanning {args.duration}s via bluez DBus...")
    devices = await BleakScanner.discover(timeout=args.duration, return_adv=True)
    rows = []
    for addr, (dev, adv) in devices.items():
        rows.append((adv.rssi if adv.rssi is not None else -999, addr, adv.local_name or ""))
    rows.sort(reverse=True)
    print(f"{'RSSI':>5}  {'MAC':<17}  name")
    for rssi, addr, name in rows:
        mark = "  <-- likely candidate" if any(h in (name or "").upper() for h in NAME_HINTS) else ""
        print(f"{rssi:>5}  {addr:<17}  {name}{mark}")


async def cmd_listen(args):
    tee = Tee(args.log)
    mac = args.mac

    # Per-characteristic stats
    stats: Dict[str, Dict] = {}
    temp_char_uuid: Optional[str] = None
    probe_values = [None] * args.num_probes

    def on_notify(characteristic, data):
        nonlocal temp_char_uuid, probe_values
        uuid = characteristic.uuid
        stats.setdefault(uuid, {"hits": 0, "good": 0, "last": None})
        s = stats[uuid]
        s["hits"] += 1
        s["last"] = bytes(data)
        tee.write(f"NOTIFY uuid={uuid} handle=0x{characteristic.handle:04x} len={len(data)} data={bytes(data).hex()}")

        # Battery-frame heuristic (iBBQ-style)
        if len(data) >= 5 and data[0] == 0x24:
            try:
                cur = int.from_bytes(data[1:3], "little")
                mx = int.from_bytes(data[3:5], "little") or 6580
                tee.write(f"  -> possible battery frame: {100*cur/mx:.1f}%")
            except Exception:
                pass

        temps, conf = heuristic_temps_c(bytes(data), args.num_probes)
        if temps is None:
            return
        if conf >= 0.75:
            s["good"] += 1
            tee.write(f"  -> heuristic temps (conf={conf:.2f}): {fmt_temps(temps)}")
            if temp_char_uuid is None and s["good"] >= 2:
                temp_char_uuid = uuid
                tee.write(f"*** LOCKED temperature characteristic uuid={uuid} ***")
            if temp_char_uuid == uuid:
                probe_values[:] = temps

    tee.write(f"connecting to {mac} via bluez DBus...")
    async with BleakClient(mac, timeout=20.0) as client:
        tee.write(f"CONNECTED mtu={client.mtu_size}")

        # Enumerate services
        notifiable = []
        writable = []
        for svc in client.services:
            tee.write(f"SERVICE uuid={svc.uuid} handle=0x{svc.handle:04x}")
            for ch in svc.characteristics:
                props = ",".join(ch.properties)
                tee.write(
                    f"  CHAR uuid={ch.uuid} handle=0x{ch.handle:04x} props={props}"
                )
                if "notify" in ch.properties or "indicate" in ch.properties:
                    notifiable.append(ch)
                if "write" in ch.properties or "write-without-response" in ch.properties:
                    writable.append(ch)

        # Subscribe to notifications
        for ch in notifiable:
            try:
                await client.start_notify(ch, on_notify)
                tee.write(f"SUBSCRIBED uuid={ch.uuid}")
            except Exception as e:
                tee.write(f"SUBSCRIBE FAILED uuid={ch.uuid}: {e}")

        # Best-effort iBBQ handshake on every writable characteristic
        if not args.no_handshake:
            payloads = [
                ("CREDENTIALS", IBBQ_CREDENTIALS),
                ("REALTIME_ON", IBBQ_REALTIME_ON),
                ("UNITS", IBBQ_UNITS_F if args.units == "F" else IBBQ_UNITS_C),
                ("BATTERY", IBBQ_BATTERY),
            ]
            for ch in writable:
                for label, payload in payloads:
                    try:
                        await client.write_gatt_char(ch, payload, response=False)
                        tee.write(f"WRITE {label} uuid={ch.uuid} payload={payload.hex()}")
                    except Exception as e:
                        tee.write(f"WRITE {label} failed uuid={ch.uuid}: {e}")

        tee.write(f"listening {args.duration}s (poll={args.poll}s)... (Ctrl-C to stop)")
        stop = asyncio.Event()

        def handle_sigint():
            tee.write("interrupted by user")
            stop.set()

        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, handle_sigint)
        except NotImplementedError:
            pass

        deadline = time.time() + args.duration
        ff01_uuid = "0000ff01-0000-1000-8000-00805f9b34fb"
        while time.time() < deadline and not stop.is_set():
            await asyncio.sleep(min(args.poll, max(0.1, deadline - time.time())))
            if stop.is_set():
                break
            if args.poll > 0:
                try:
                    val = await client.read_gatt_char(ff01_uuid)
                    tee.write(f"POLL uuid={ff01_uuid} len={len(val)} data={bytes(val).hex()}")
                    # Feed it through on_notify-style decoding by synthesizing
                    class _C:
                        uuid = ff01_uuid
                        handle = 0x0015
                    on_notify(_C(), val)
                except Exception as e:
                    tee.write(f"POLL failed: {e}")

        tee.write("=== final per-characteristic stats ===")
        for uuid, s in stats.items():
            tee.write(
                f"  uuid={uuid} hits={s['hits']} good={s['good']} "
                f"last={(s['last'].hex() if s['last'] else '-')}"
            )
        if temp_char_uuid:
            tee.write(f"temperature source: uuid={temp_char_uuid}")
        else:
            tee.write("no characteristic matched the 4 x uint16 LE tenths-of-degC heuristic.")

    tee.close()


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan")
    s.add_argument("--duration", type=float, default=10.0)
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("listen")
    l.add_argument("mac")
    l.add_argument("--duration", type=float, default=120.0)
    l.add_argument("--num-probes", type=int, default=4)
    l.add_argument("--units", choices=("C", "F"), default="F")
    l.add_argument("--log", default="bt_int14bw_trace.log")
    l.add_argument("--no-handshake", action="store_true")
    l.add_argument("--poll", type=float, default=5.0,
                   help="seconds between explicit reads of 0xFF01 (0 disables polling)")
    l.set_defaults(func=cmd_listen)
    return p


def main():
    args = build_parser().parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
