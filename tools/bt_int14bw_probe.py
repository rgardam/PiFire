#!/usr/bin/env python3
"""Standalone BLE probe/experiment tool for the Inkbird INT-14-BW.

Runs outside PiFire. Connects to the device, enumerates every service and
characteristic, subscribes to notifications on every notifiable one, attempts
the legacy iBBQ magic-bytes handshake, and prints/logs every frame it sees.
Applies a heuristic parser (4 x uint16 LE tenths-of-degC) and reports live
when a characteristic looks like the temperature source.

Requires: bluepy (`pip install bluepy==1.3.0`, plus `libglib2.0-dev`),
          and on Linux `sudo setcap 'cap_net_raw,cap_net_admin+eip' $(python -c
          "import bluepy,os;print(os.path.join(os.path.dirname(bluepy.__file__),
          'bluepy-helper'))")` to avoid running as root.

Usage:
  sudo python3 bt_int14bw_probe.py scan
  sudo python3 bt_int14bw_probe.py listen AA:BB:CC:DD:EE:FF
  sudo python3 bt_int14bw_probe.py listen          # auto-pick by name match
  sudo python3 bt_int14bw_probe.py listen --duration 120 --log trace.log

Ctrl-C cleanly disconnects and flushes the log.
"""
import argparse
import logging
import os
import signal
import sys
import time

from bluepy.btle import (
    ADDR_TYPE_PUBLIC,
    ADDR_TYPE_RANDOM,
    BTLEDisconnectError,
    BTLEException,
    DefaultDelegate,
    Peripheral,
    Scanner,
)

CCCD_UUID = 0x2902
CCCD_NOTIFY_ON = bytearray.fromhex("0100")

IBBQ_CREDENTIALS = bytearray.fromhex("21 07 06 05 04 03 02 01 b8 22 00 00 00 00 00")
IBBQ_REALTIME_ON = bytearray.fromhex("0B 01 00 00 00 00")
IBBQ_UNITS_C = bytearray.fromhex("02 00 00 00 00 00")
IBBQ_UNITS_F = bytearray.fromhex("02 01 00 00 00 00")
IBBQ_BATTERY = bytearray.fromhex("08 24 00 00 00 00")

PLAUSIBLE_TEMP_C_MIN = -20.0
PLAUSIBLE_TEMP_C_MAX = 300.0
UNPLUGGED_MARKERS = {0xFFFF, 0xFFF6}

NAME_MATCHES = ("INT-14", "INKBIRD", "IBBQ", "XBBQ")


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class Tee:
    """Write to stdout and a log file at once."""

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


def heuristic_temps_c(data, num_probes):
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
    out = []
    for t in temps:
        out.append("unplugged" if t is None else f"{t:6.1f}C / {t*9/5+32:5.1f}F")
    return " | ".join(out)


class NotifyDelegate(DefaultDelegate):

    def __init__(self, tee, char_by_handle, num_probes):
        super().__init__()
        self.tee = tee
        self.char_by_handle = char_by_handle
        self.num_probes = num_probes
        self.stats = {}  # handle -> {hits, good, uuid, last}
        self.temp_handle = None

    def handleNotification(self, cHandle, data):
        data = bytes(data)
        uuid = self.char_by_handle.get(cHandle, "?")
        st = self.stats.setdefault(
            cHandle, {"hits": 0, "good": 0, "uuid": str(uuid), "last": None}
        )
        st["hits"] += 1
        st["last"] = data
        self.tee.write(
            f"NOTIFY handle=0x{cHandle:04x} uuid={uuid} len={len(data)} data={data.hex()}"
        )

        if len(data) >= 5 and data[0] == 0x24:
            try:
                cur = int.from_bytes(data[1:3], "little")
                mx = int.from_bytes(data[3:5], "little") or 6580
                self.tee.write(f"  -> possible battery frame: {100*cur/mx:.1f}%")
            except Exception:
                pass

        temps, conf = heuristic_temps_c(data, self.num_probes)
        if temps is None:
            return
        if conf >= 0.75:
            st["good"] += 1
            self.tee.write(
                f"  -> heuristic temps (conf={conf:.2f}): {fmt_temps(temps)}"
            )
            if self.temp_handle is None and st["good"] >= 2:
                self.temp_handle = cHandle
                self.tee.write(
                    f"*** LOCKED temperature handle=0x{cHandle:04x} uuid={uuid} ***"
                )


def cmd_scan(args):
    print(f"scanning for {args.duration}s (needs sudo / BT caps)...")
    scanner = Scanner()
    devs = scanner.scan(args.duration)
    if not devs:
        print("no devices found.")
        return
    rows = []
    for d in devs:
        name = None
        for (_ad, desc, val) in d.getScanData():
            if desc in ("Complete Local Name", "Shortened Local Name"):
                name = val
                break
        rows.append((d.rssi, d.addr, d.addrType, name or ""))
    rows.sort(reverse=True)
    print(f"{'RSSI':>5}  {'MAC':<17}  {'type':<6}  name")
    for rssi, addr, atype, name in rows:
        mark = ""
        if any(m in (name or "").upper() for m in NAME_MATCHES):
            mark = "  <-- likely candidate"
        print(f"{rssi:>5}  {addr:<17}  {atype:<6}  {name}{mark}")


def pick_device(duration):
    scanner = Scanner()
    devs = scanner.scan(duration)
    best = None
    best_rssi = -999
    for d in devs:
        name = None
        for (_ad, desc, val) in d.getScanData():
            if desc in ("Complete Local Name", "Shortened Local Name"):
                name = val
                break
        if name and any(m in name.upper() for m in NAME_MATCHES):
            if d.rssi > best_rssi:
                best = (d.addr, d.addrType, name)
                best_rssi = d.rssi
    return best


def cmd_listen(args):
    tee = Tee(args.log)

    # Resolve target
    if args.mac:
        target = (args.mac, None, "(from CLI)")
        tee.write(f"using CLI-provided MAC {args.mac}")
    else:
        tee.write(f"scanning {args.scan_duration}s to auto-pick device...")
        target = pick_device(args.scan_duration)
        if target is None:
            tee.write("no INT-14-BW / INKBIRD / iBBQ device found in scan.")
            tee.close()
            sys.exit(1)
        tee.write(f"auto-picked {target[0]} addr_type={target[1]} name={target[2]!r}")

    mac = target[0]
    addr_types = (target[1],) if target[1] else (ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM)

    # Connect
    peripheral = None
    last_exc = None
    for atype in addr_types:
        try:
            tee.write(f"connecting to {mac} (addr_type={atype})...")
            peripheral = Peripheral(mac, addrType=atype)
            tee.write(f"CONNECTED addr_type={atype}")
            break
        except BTLEException as e:
            tee.write(f"  connect failed: {e}")
            last_exc = e
    if peripheral is None:
        tee.write(f"could not connect: {last_exc}")
        tee.close()
        sys.exit(1)

    # Enumerate
    char_by_handle = {}
    notify_chars = []
    writable_chars = []

    try:
        services = list(peripheral.getServices())
    except Exception as e:
        tee.write(f"getServices failed: {e}")
        services = []

    for svc in services:
        tee.write(f"SERVICE uuid={svc.uuid}")
        try:
            chars = svc.getCharacteristics()
        except Exception as e:
            tee.write(f"  getCharacteristics failed: {e}")
            continue
        for ch in chars:
            try:
                props = ch.propertiesToString()
            except Exception:
                props = ""
            handle = ch.getHandle()
            char_by_handle[handle] = str(ch.uuid)
            tee.write(
                f"  CHAR uuid={ch.uuid} handle=0x{handle:04x} props={props}"
            )
            if "NOTIFY" in props or "INDICATE" in props:
                notify_chars.append(ch)
            if "WRITE" in props:
                writable_chars.append(ch)

    delegate = NotifyDelegate(tee, char_by_handle, args.num_probes)
    peripheral.setDelegate(delegate)

    # Enable notifications
    for ch in notify_chars:
        try:
            cccds = ch.getDescriptors(forUUID=CCCD_UUID)
            if cccds:
                cccds[0].write(CCCD_NOTIFY_ON, withResponse=True)
                tee.write(f"CCCD-ON handle=0x{ch.getHandle():04x} uuid={ch.uuid}")
        except Exception as e:
            tee.write(f"CCCD-ON failed handle=0x{ch.getHandle():04x}: {e}")

    # Optional iBBQ-style handshake on every writable characteristic
    if not args.no_handshake:
        payloads = [
            ("CREDENTIALS", IBBQ_CREDENTIALS),
            ("REALTIME_ON", IBBQ_REALTIME_ON),
            ("UNITS", IBBQ_UNITS_F if args.units == "F" else IBBQ_UNITS_C),
            ("BATTERY", IBBQ_BATTERY),
        ]
        for ch in writable_chars:
            for label, payload in payloads:
                try:
                    ch.write(payload, withResponse=False)
                    tee.write(
                        f"WRITE {label} handle=0x{ch.getHandle():04x} payload={payload.hex()}"
                    )
                except Exception as e:
                    tee.write(
                        f"WRITE {label} failed 0x{ch.getHandle():04x}: {e}"
                    )

    # Listen loop
    tee.write(
        f"listening for notifications ({'forever' if args.duration is None else f'{args.duration}s'})... Ctrl-C to stop"
    )
    stop_at = None if args.duration is None else time.time() + args.duration

    def handle_sigint(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        last_report = 0
        while True:
            if stop_at and time.time() >= stop_at:
                break
            try:
                peripheral.waitForNotifications(1.0)
            except BTLEDisconnectError:
                tee.write("device disconnected")
                break
            now = time.time()
            if now - last_report >= 10:
                last_report = now
                total = sum(s["hits"] for s in delegate.stats.values())
                tee.write(
                    f"summary: {total} notifications across {len(delegate.stats)} characteristics; "
                    f"locked temp handle={('0x%04x' % delegate.temp_handle) if delegate.temp_handle else 'none'}"
                )
    except KeyboardInterrupt:
        tee.write("interrupted by user")
    finally:
        try:
            peripheral.disconnect()
        except Exception:
            pass

        # Final summary
        tee.write("=== final per-characteristic stats ===")
        for handle, s in sorted(delegate.stats.items()):
            tee.write(
                f"  handle=0x{handle:04x} uuid={s['uuid']} hits={s['hits']} good={s['good']} "
                f"last={(s['last'].hex() if s['last'] else '-')}"
            )
        if delegate.temp_handle is not None:
            tee.write(
                f"temperature source: handle=0x{delegate.temp_handle:04x} "
                f"uuid={char_by_handle.get(delegate.temp_handle, '?')}"
            )
        else:
            tee.write(
                "no characteristic matched the 4 x uint16 LE tenths-of-degC heuristic."
            )
            tee.write(
                "  -> inspect the per-handle 'last' frames above; the temperature"
            )
            tee.write(
                "     packet is likely one of them with a different byte layout."
            )

        tee.close()


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan for nearby BLE devices")
    s.add_argument("--duration", type=float, default=10.0, help="scan seconds")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("listen", help="connect to device and dump BLE traffic")
    l.add_argument("mac", nargs="?", help="MAC address (omit to auto-pick)")
    l.add_argument("--scan-duration", type=float, default=10.0,
                   help="scan time when auto-picking a device")
    l.add_argument("--duration", type=float, default=None,
                   help="listen seconds (default: forever)")
    l.add_argument("--num-probes", type=int, default=4)
    l.add_argument("--units", choices=("C", "F"), default="F")
    l.add_argument("--log", default="bt_int14bw_trace.log")
    l.add_argument("--no-handshake", action="store_true",
                   help="skip iBBQ magic-bytes writes (cleaner log)")
    l.set_defaults(func=cmd_listen)
    return p


def main():
    logging.basicConfig(level=logging.WARNING)
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
