##############################################################################
#
# Module: link_analyzer_test.py
#
# Description:
#     Automated Link Analyzer regression test framework using the
#     RWC Tester API. This script configures protocol and RF parameters,
#     executes human-readable MAC command payloads, transmits downlink
#     frames, and parses uplink responses for validation and logging.
#
# Author:
#     Vinay N, MCCI Corporation
#
# Revision history:
#     V2.0.0  Feb 2026  Vinay N
##############################################################################
import sys
import time
import os
import re
from enum import Enum

import csv
from datetime import datetime


sys.path.insert(0, os.path.abspath('..'))
from rwclib.cRWC5020x import RWCTesterApi


# ------------------ HUMAN READABLE COMMANDS ------------------

class Command(Enum):
    READ          = "00"
    WRITE         = "01"
    RESET_DEVICE  = "02"
    GET_VERSION   = "03"
    RESET_APPEUI  = "04"
    REJOIN        = "05"


class Register(Enum):
    ENERGY_POS1_I32   = "0BB9"
    ENERGY_POS2_I32   = "0BBB"
    ENERGY_POS3_I32   = "0BBD"
    ENERGY_NEG1_I32   = "0BBF"
    ENERGY_NEG2_I32   = "0BC1"
    ENERGY_NEG3_I32   = "0BC3"
    DEMAND1_F32       = "0BC5"
    DEMAND2_F32       = "0BC7"
    DEMAND3_F32       = "0BC9"
    METERCONFIG1_I16  = "0BCB"
    METERCONFIG2_I16  = "0BCC"
    METERCONFIG3_I16  = "0BCD"


# ------------------ MAIN TEST CLASS ------------------

class LinkAnalyzerTest(RWCTesterApi):

    def __init__(self, port, addr=None):
        """
        Function: __init__

        Description:
            Initializes the Link Analyzer test object, establishes
            communication with the RWC tester, opens the configured
            port, and prepares CSV logging infrastructure.

        Parameters:
            port (str): Communication port identifier
            addr (str): Tester IP address (optional)

        Returns:
            None
        """
        RWCTesterApi.__init__(self, port, addr)
        RWCTesterApi.open_port(self)

        self.tag_counter = 1

        # ---- Port-1 boot counter cache ----
        # Populated opportunistically whenever a Port-1 uplink with a
        # boot byte is observed during the regression. Used by
        # handle_reset_response() to skip the boot_before wait when a
        # recent value is already known.
        self.last_known_boot = None

        # ---- CSV setup (single file, append mode) ----
        self.csv_file = "rwc_mac_log.csv"

        # Write header ONLY if file does not exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["COMMAND", "DOWNLINK_PAYLOAD", "UPLINK_PAYLOAD", "RESULT"])
    
    def log_new_cycle(self):
        """
        Function: log_new_cycle

        Description:
            Inserts a separator entry in the CSV log file to indicate
            the start of a new MAC command test cycle.

        Returns:
            None
        """
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            # writer.writerow(["---- NEW TEST CYCLE ----", "", ""])
            writer.writerow(["------------- DOWNLINK COMMANDS -------------", "", "", ""])

    def build_payload(self, command: Command, register: Register = None, data_hex: str = None):
        """
        Function: build_payload

        Description:
            Dynamically constructs a MAC command payload using
            human-readable command and register inputs.

            WRITE → CMD + TAG + REG + DATA
            READ  → CMD + TAG + REG + COUNT

        Parameters:
            command   (Command): MAC command enum
            register  (Register): Target register enum
            data_hex  (str): Data value or read count

        Returns:
            str: Encoded hexadecimal payload
        """

        # Auto increment tag
        tag_hex = f"{self.tag_counter:02X}"
        self.tag_counter += 1

        payload = command.value + tag_hex

        # Append register
        if register:
            payload += register.value

        # READ: data_hex = read count (01 / 02 / etc)
        if command == Command.READ:
            if not data_hex:
                raise ValueError("READ command requires read count (e.g. '01' or '02')")
            payload += data_hex

        # WRITE: data_hex = value
        elif command == Command.WRITE:
            if not data_hex:
                raise ValueError("WRITE command requires data value")
            payload += data_hex.upper()

        # REJOIN: data_hex = delay in seconds (2-byte big-endian, 4 hex chars)
        elif command == Command.REJOIN:
            if not data_hex:
                raise ValueError("REJOIN command requires delay seconds (2-byte BE hex)")
            if len(data_hex) != 4:
                raise ValueError("REJOIN delay must be 4 hex chars (2 bytes BE)")
            payload += data_hex.upper()

        return payload


    def config_link_screen(self):
        """
        Function: config_link_screen

        Description:
            Configures the tester UI to Link Analyzer mode by
            setting the required test mode and submenu screen.

        Returns:
            None
        """
        screenparamdict = {'testmode': 'EDT', 'submenu': 'LINK'}

        print('Setting up Test Mode to EDT')
        RWCTesterApi.set_mode(self, screenparamdict.get('testmode'))
        mymode = RWCTesterApi.query_mode(self)
        print('Test Mode: {}\n'.format(mymode))

        RWCTesterApi.set_screen(self, screenparamdict.get('submenu'))
        print("config_link_screen done\n")

    def config_protocol(self):
        """
        Function: config_protocol

        Description:
            Configures LoRaWAN protocol parameters including
            region, protocol version, device class, activation
            procedure, EUIs, and application keys.

        Returns:
            None
        """
        print('Setting up PROTOCOL parameters')

        DEV_EUI_HEX = "0002CC0200992301"
        APP_EUI_HEX = "0000000000000001"
        APP_KEY_HEX = "00000000000000000000000000000007"

        dev_eui_val = int(DEV_EUI_HEX, 16)
        app_eui_val = int(APP_EUI_HEX, 16)
        app_key_val = int(APP_KEY_HEX, 16)

        RWCTesterApi.protocol_setregion(self, "IN_866")
        print("Protocol Region:", RWCTesterApi.protocol_getregion(self))

        RWCTesterApi.protocol_setprotocolver(self, "LoRaWAN1.0.3")
        print("Protocol Version:", RWCTesterApi.protocol_getprotocolver(self))

        RWCTesterApi.protocol_setclass(self, "A")
        print("Protocol Class:", RWCTesterApi.protocol_getclass(self))

        RWCTesterApi.protocol_setactivationprocedure(self, "OTAA")
        print("Activation Procedure:", RWCTesterApi.protocol_getactivationprocedure(self))

        RWCTesterApi.protocol_settestmodeflag(self, "OFF")
        print("Test Mode Status:", RWCTesterApi.protocol_gettestmodeflag(self))

        RWCTesterApi.protocol_seteuival(self, dev_eui_val)
        print("DEV_EUI (RWC read):", RWCTesterApi.protocol_geteuival(self))

        RWCTesterApi.protocol_setappeui(self, app_eui_val)
        print("APP_EUI (RWC read):", RWCTesterApi.protocol_getappeui(self))

        RWCTesterApi.protocol_setappkey(self, app_key_val)
        print("APP_KEY (RWC read):", RWCTesterApi.protocol_getappkey(self))

        RWCTesterApi.protocol_seteuiflag(self, "YES")
        print("EUI Check:", RWCTesterApi.protocol_geteuiflag(self))
        print("\nconfig_protocol done\n")

    def config_rf(self):
        """
        Function: config_rf

        Description:
            Sets RF transmission parameters such as transmit power,
            path loss, frequency offset, and timing offset for
            Link Analyzer testing.

        Returns:
            None
        """
        rfparamdict = {'txpow': -30, 'pathloss': 0, 'freqoffset': 0, 'timeoffset': 0}

        print('Setting up RF parameters')
        RWCTesterApi.rf_settxpower(self, rfparamdict.get('txpow'))
        print('RF Tx Power:', RWCTesterApi.rf_gettxpower(self))

        RWCTesterApi.rf_setpathloss(self, rfparamdict.get('pathloss'))
        print('RF Path Loss:', RWCTesterApi.rf_getpathloss(self))

        RWCTesterApi.rf_setfreqoffset(self, rfparamdict.get('freqoffset'))
        print('RF Frequency Offset:', RWCTesterApi.rf_getfreqoffset(self))

        RWCTesterApi.rf_settimeoffset(self, rfparamdict.get('timeoffset'))
        print('RF Time Offset:', RWCTesterApi.rf_gettimeoffset(self))
        print("\nconfig_rf done\n")

    def hex_payload_to_int_and_size(self, hex_str):
        """
        Function: hex_payload_to_int_and_size

        Description:
            Converts a hexadecimal payload string into its integer
            representation and calculates the payload size in bytes.

        Parameters:
            hex_str (str): Hexadecimal payload string

        Returns:
            tuple:
                payload_int  (int)
                payload_size (int)
        """
        hex_str = hex_str.replace(" ", "")
        payload_bytes = bytes.fromhex(hex_str)
        payload_int = int.from_bytes(payload_bytes, "big")
        payload_size = len(payload_bytes)
        return payload_int, payload_size

    def parse_uplink_payload(self, msg):
        """
        Function: parse_uplink_payload

        Description:
            Extracts the FRMPayload from a DataUp log message.
            Handles hidden characters and safely parses valid
            hexadecimal byte pairs from the LoRaWAN frame.

        Parameters:
            msg (str): Raw uplink log message

        Returns:
            str : Parsed FRMPayload in hexadecimal format
            None: If parsing fails or payload not present
        """
        try:
            if "]" not in msg:
                return None

            hex_part = msg.split("]")[1]
            hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", hex_part)

            if len(hex_bytes) < 13:
                return None

            frame = [int(b, 16) for b in hex_bytes]

            MHDR_LEN     = 1
            DEVADDR_LEN  = 4
            FCTRL_LEN    = 1
            FCNT_LEN     = 2
            FPORT_LEN    = 1
            MIC_LEN      = 4

            payload_start = (
                MHDR_LEN +
                DEVADDR_LEN +
                FCTRL_LEN +
                FCNT_LEN +
                FPORT_LEN
            )

            payload_end = len(frame) - MIC_LEN

            if payload_end <= payload_start:
                return None

            payload_bytes = frame[payload_start:payload_end]
            payload_hex = " ".join(f"{b:02X}" for b in payload_bytes)

            return payload_hex

        except Exception as e:
            print("Failed to parse uplink payload:", e)
            return None

    def extract_fport(self, msg):
        """
        Function: extract_fport

        Description:
            Extracts the FPort byte from an uplink frame, honoring
            FOptsLen from the FCtrl byte (bits [3:0]). Returns None
            if the frame is too short or has no FPort field
            (e.g. NoPayload uplinks).

        Parameters:
            msg (str): Raw uplink log message

        Returns:
            int : FPort value (0-255)
            None: If frame has no FPort or parsing fails
        """
        try:
            if "]" not in msg:
                return None

            hex_part = msg.split("]")[1]
            hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", hex_part)

            if len(hex_bytes) < 13:
                return None

            fctrl = int(hex_bytes[5], 16)
            fopts_len = fctrl & 0x0F
            fport_idx = 1 + 4 + 1 + 2 + fopts_len

            if len(hex_bytes) <= fport_idx + 4:
                return None

            return int(hex_bytes[fport_idx], 16)

        except Exception as e:
            print("Failed to extract FPort:", e)
            return None

    def drain_uplinks(self):
        """
        Function: drain_uplinks

        Description:
            Drains all pending uplink messages from the tester's
            buffer by reading link_readmsg until "NA" is returned.
            Used before sending each downlink to ensure the wait
            loop only sees uplinks generated by the current command.

        Returns:
            None
        """
        drained = 0
        while True:
            msg = RWCTesterApi.link_readmsg(self)
            if not msg or msg == "NA":
                break
            self.cache_boot_if_port1(msg)
            drained += 1
        if drained:
            print(f"Drained {drained} stale uplink message(s)")

    def extract_devaddr(self, msg):
        """
        Function: extract_devaddr

        Description:
            Extracts the LoRaWAN DevAddr (4 bytes) from an uplink log
            message. The PHYPayload stores DevAddr little-endian on the
            wire, so the bytes are reversed for big-endian display.

        Parameters:
            msg (str): Raw uplink log message

        Returns:
            str : DevAddr in big-endian hex (e.g. "01ABCDEF")
            None: If parsing fails
        """
        try:
            if "]" not in msg:
                return None

            hex_part = msg.split("]")[1]
            hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", hex_part)

            if len(hex_bytes) < 5:
                return None

            devaddr_le = hex_bytes[1:5]
            devaddr_be = "".join(reversed(devaddr_le))
            return devaddr_be.upper()

        except Exception as e:
            print("Failed to extract DevAddr:", e)
            return None

    def handle_rejoin_response(self, payload_hex, delay_secs):
        """
        Function: handle_rejoin_response

        Description:
            Handles the multi-stage REJOIN response flow that cannot be
            covered by the standard wait loop:

                Stage 1: Wait up to (delay_secs + 60) s for the ACK
                         uplink [05][tag][00]; capture OLD_DEVADDR.
                         The firmware suspends keepalive uplinks during
                         its spin loop, so the ACK only transmits after
                         the device-side delay completes — the timeout
                         must scale with delay_secs.
                Stage 2: Watch the log stream up to 60 s for the
                         "Join-request" and "Join-accept" markers.
                Stage 3: Wait up to 90 s for a post-rejoin DataUp or
                         NoPayload uplink; capture POST_REJOIN_DEVADDR.
                Stage 4: Compose status strings for CSV and console.

        Parameters:
            payload_hex (str): Downlink REJOIN payload (for logging)
            delay_secs  (int): Device-side rejoin delay in seconds

        Returns:
            tuple:
                uplink_payload (str): Parsed FRMPayload from Stage 1
                                      ACK, or "NO_UPLINK" if missing.
                result         (str): Short status (REJOIN_OK,
                                      REJOIN_FAIL_NO_ACCEPT,
                                      REJOIN_FAIL_NO_JOINREQ, or
                                      NO_UPLINK) for the CSV
                                      RESULT column. Verbose status
                                      with DevAddr details is printed
                                      to console only.
        """
        old_devaddr = None
        new_devaddr = None
        saw_join_request = False
        saw_join_accept = False
        expected_tag = payload_hex[2:4].upper()
        ack_payload = None

        # ---- Stage 1: wait for port-3 REJOIN ACK uplink ----
        # Timeout scales with delay_secs because the firmware suspends
        # keepalive uplinks during its spin loop; the ACK only goes out
        # after the device-side delay completes.
        ack_window = delay_secs + 60
        print(f"REJOIN Stage 1: waiting for ACK uplink (port 3, up to {ack_window} s)...")
        ack_timeout = time.time() + ack_window
        got_ack = False
        while time.time() < ack_timeout:
            msg = RWCTesterApi.link_readmsg(self)
            if not msg or msg == "NA":
                time.sleep(1)
                continue
            self.cache_boot_if_port1(msg)
            if "DataUp" in str(msg):
                fport = self.extract_fport(msg)
                if fport != 3:
                    print(f"Ignoring uplink on port {fport} (waiting for port 3)")
                    continue
                parsed = self.parse_uplink_payload(msg)
                if not parsed:
                    continue
                fp_bytes = parsed.split()
                cmd_got = fp_bytes[0].upper() if len(fp_bytes) >= 1 else "?"
                tag_got = fp_bytes[1].upper() if len(fp_bytes) >= 2 else "?"
                if cmd_got != "05" or tag_got != expected_tag:
                    print(f"Ignoring port-3 frame (cmd={cmd_got}, tag={tag_got}; "
                          f"expected cmd=05, tag={expected_tag})")
                    continue
                ack_payload = parsed
                old_devaddr = self.extract_devaddr(msg)
                print("Parsed FRMPayload:", parsed)
                print("REJOIN ACK received. OLD_DEVADDR:", old_devaddr)
                got_ack = True
                break
            time.sleep(1)

        if not got_ack:
            return "NO_UPLINK", "NO_UPLINK"

        # ---- Stage 2: watch for Join-request / Join-accept ----
        # No additional sleep needed: the ACK already arrived after the
        # firmware's delay completed, so the join exchange follows
        # within a few seconds.
        print("REJOIN Stage 2: watching for Join-request / Join-accept (60 s)...")
        join_timeout = time.time() + 60
        while time.time() < join_timeout:
            msg = RWCTesterApi.link_readmsg(self)
            if not msg or msg == "NA":
                time.sleep(1)
                continue

            self.cache_boot_if_port1(msg)

            if "Join-request" in str(msg):
                print(">>>", msg)
                saw_join_request = True
            if "Join-accept" in str(msg):
                print(">>>", msg)
                saw_join_accept = True

            if saw_join_request and saw_join_accept:
                break

            time.sleep(1)

        # ---- Stage 3: wait for any post-rejoin uplink to confirm device alive ----
        if saw_join_accept:
            print("REJOIN Stage 3: waiting up to 90 s for post-rejoin uplink...")
            post_timeout = time.time() + 90
            while time.time() < post_timeout:
                msg = RWCTesterApi.link_readmsg(self)
                if not msg or msg == "NA":
                    time.sleep(1)
                    continue
                self.cache_boot_if_port1(msg)
                if "DataUp" in str(msg) or "NoPayload" in str(msg):
                    new_devaddr = self.extract_devaddr(msg)
                    print("Post-rejoin uplink received. POST_REJOIN_DEVADDR:", new_devaddr)
                    break
                time.sleep(1)

        # ---- Stage 4: compose short result (for CSV) and verbose
        # status (console only). Success criterion: Join-accept seen.
        # DevAddr is informational (static in this test setup, will
        # not change across rejoin).
        old_str = old_devaddr if old_devaddr else "UNKNOWN"
        new_str = new_devaddr if new_devaddr else "UNKNOWN"

        if saw_join_accept:
            short_status = "REJOIN_OK"
            parts = ["REJOIN_OK", f"OLD_DEVADDR={old_str}"]
            parts.append(f"JOIN_REQ={'YES' if saw_join_request else 'NO'}")
            if new_devaddr:
                parts.append(f"POST_REJOIN_DEVADDR={new_str}")
            verbose_status = " | ".join(parts)
        elif saw_join_request:
            short_status = "REJOIN_FAIL_NO_ACCEPT"
            verbose_status = f"REJOIN_FAIL_NO_ACCEPT | OLD_DEVADDR={old_str}"
        else:
            short_status = "REJOIN_FAIL_NO_JOINREQ"
            verbose_status = f"REJOIN_FAIL_NO_JOINREQ | OLD_DEVADDR={old_str}"

        print("REJOIN result:", verbose_status)
        return ack_payload, short_status

    def extract_boot_from_port1(self, msg):
        """
        Function: extract_boot_from_port1

        Description:
            Parses a Port-1 uplink FRMPayload (command byte 0x19)
            and returns the boot counter byte if present.

            Format reference: m4811-firmware/extra/m4811-decoder-ttn.js
                byte 0     = 0x19
                byte 1     = flags (bit 0=vBat, bit 1=boot, ...)
                byte 2..3  = vBat (uint16 BE) if flags & 0x01
                byte 2 or 4 = boot (uint8)    if flags & 0x02

        Parameters:
            msg (str): Raw uplink log message

        Returns:
            int : boot counter value (0..255)
            None: If frame is not Port-1 / not 0x19 / no boot field
        """
        parsed = self.parse_uplink_payload(msg)
        if not parsed:
            return None
        fp = parsed.split()
        if len(fp) < 2 or fp[0].upper() != "19":
            return None
        flags = int(fp[1], 16)
        if not (flags & 0x02):
            return None
        offset = 4 if (flags & 0x01) else 2
        if len(fp) <= offset:
            return None
        return int(fp[offset], 16)

    def cache_boot_if_port1(self, msg):
        """
        Function: cache_boot_if_port1

        Description:
            Opportunistic boot-counter cache updater. Inspects an
            uplink message; if it is a Port-1 DataUp carrying a
            parseable boot byte, updates self.last_known_boot.
            Called from every message-reading site so the cache
            stays current across the regression run.

        Parameters:
            msg (str): Raw uplink log message

        Returns:
            None
        """
        if not msg or msg == "NA":
            return
        if "DataUp" not in str(msg):
            return
        if self.extract_fport(msg) != 1:
            return
        boot = self.extract_boot_from_port1(msg)
        if boot is None:
            return
        if self.last_known_boot != boot:
            print(f"[boot-cache] updated: {self.last_known_boot} -> {boot}")
        self.last_known_boot = boot

    def wait_for_port1_boot(self, timeout_secs):
        """
        Function: wait_for_port1_boot

        Description:
            Blocks until the next Port-1 uplink with a boot byte
            arrives, or the timeout expires. Also updates the boot
            cache as a side effect.

        Parameters:
            timeout_secs (int): Max wait window in seconds

        Returns:
            int : Boot counter value
            None: If no Port-1 uplink with boot arrived in time
        """
        deadline = time.time() + timeout_secs
        while time.time() < deadline:
            msg = RWCTesterApi.link_readmsg(self)
            if not msg or msg == "NA":
                time.sleep(1)
                continue
            self.cache_boot_if_port1(msg)
            if "DataUp" in str(msg) and self.extract_fport(msg) == 1:
                boot = self.extract_boot_from_port1(msg)
                if boot is not None:
                    return boot
            time.sleep(1)
        return None

    def handle_reset_response(self):
        """
        Function: handle_reset_response

        Description:
            Handles the RESET_DEVICE response flow using the
            Port-1 boot-counter as gold-standard reset evidence.
            The firmware sends no reply for this downlink; the
            only authoritative signal that a reset happened is
            the boot counter byte inside the Port-1 data frame,
            which increments on every device reboot.

                Step 1: Capture boot_before. Prefer the
                        opportunistic cache (self.last_known_boot)
                        if populated; otherwise wait up to 7 min
                        for the next Port-1 uplink.
                Step 2: Send the RESET_DEVICE downlink. (This
                        handler is invoked *before* exec_mac in
                        config_mac, so the send happens here.)
                Step 3: Wait up to 8 min for the next Port-1
                        uplink and read boot_after.
                Step 4: Compare. boot_after != boot_before is
                        proof the device rebooted. Update the
                        cache so subsequent RESET tests can skip
                        Step 1's wait.

        Returns:
            tuple:
                uplink_payload (str): Always "NO_REPLY" (firmware
                                      sends no FRMPayload).
                result         (str): One of:
                                      RESET_OK | boot a->b
                                      RESET_FAIL_NO_REBOOT
                                      RESET_FAIL_NO_PORT1_PRE
                                      RESET_FAIL_NO_PORT1_POST
        """
        # ---- Step 1: capture boot_before ----
        if self.last_known_boot is not None:
            boot_before = self.last_known_boot
            print(f"RESET Step 1: using cached boot_before = {boot_before}")
        else:
            print("RESET Step 1: waiting for Port-1 uplink for boot_before (up to 7 min)...")
            boot_before = self.wait_for_port1_boot(420)
            if boot_before is None:
                return "NO_REPLY", "RESET_FAIL_NO_PORT1_PRE"
            print(f"RESET boot_before = {boot_before}")

        # ---- Step 2: send the reset downlink ----
        print("RESET Step 2: sending reset downlink...")
        self.exec_mac()

        # ---- Step 3: capture boot_after (always a fresh read) ----
        print("RESET Step 3: waiting for Port-1 uplink for boot_after (up to 8 min)...")
        boot_after = self.wait_for_port1_boot(480)
        if boot_after is None:
            return "NO_REPLY", f"RESET_FAIL_NO_PORT1_POST | boot_before={boot_before}"
        print(f"RESET boot_after = {boot_after}")

        # ---- Step 4: compare and update cache ----
        self.last_known_boot = boot_after
        if boot_after != boot_before:
            result = f"RESET_OK | boot {boot_before}->{boot_after}"
        else:
            result = f"RESET_FAIL_NO_REBOOT | boot stays at {boot_before}"
        print(f"RESET result: {result}")
        return "NO_REPLY", result

    def config_mac(self):
        """
        Function: config_mac

        Description:
            Configures and executes sequential MAC command
            payloads. Sends downlink frames, waits for uplink
            responses, parses FRMPayload data, and logs results
            into the CSV report.

        Returns:
            None
        """
        FPORT = 3
        # 🔹 Mark start of new test cycle in CSV
        self.log_new_cycle()

        # Human readable test cases
        payloads = [
            (Command.GET_VERSION,),
            (Command.RESET_APPEUI,),
            (Command.RESET_DEVICE,),
            (Command.RESET_DEVICE,),
            # (Command.RESET_DEVICE,),

            # (Command.WRITE, Register.ENERGY_POS2_I32, "000E000A"),
            # (Command.READ,  Register.ENERGY_POS2_I32, "02"),

            # (Command.WRITE, Register.ENERGY_POS3_I32, "000B000C"),
            # (Command.READ,  Register.ENERGY_POS3_I32, "02"),
            
            # (Command.WRITE, Register.ENERGY_NEG1_I32, "000D"),
            # (Command.READ,  Register.ENERGY_NEG1_I32, "01"),

            # (Command.WRITE, Register.METERCONFIG2_I16, "00FF"),
            # (Command.READ,  Register.METERCONFIG2_I16, "01"),

            (Command.REJOIN, None, "0005"),
            # (Command.REJOIN, None, "00B4"),
        ]

        RWCTesterApi.link_setnumofmaccmd(self, 1)

        for item in payloads:
            cmd  = item[0]
            reg  = item[1] if len(item) > 1 else None
            data = item[2] if len(item) > 2 else None

            # -------- BUILD HUMAN READABLE COMMAND NAME --------
            if reg:
                command_name = f"{cmd.name} {reg.name}"
            else:
                command_name = cmd.name

            payload_hex = self.build_payload(cmd, reg, data)
            payload_int, payload_size = self.hex_payload_to_int_and_size(payload_hex)
            expected_tag = payload_hex[2:4].upper()

            print("\n--------------------------------------------")
            print(f"Sending MAC Payload: {command_name} -> 0x{payload_hex}")

            RWCTesterApi.link_setinstantmaccmd(self, 1, "USER_DEFINED")
            RWCTesterApi.link_setfport(self, FPORT)
            RWCTesterApi.link_setpayloadsize(self, payload_size)
            RWCTesterApi.link_setpayload(self, payload_int, payload_size)
            RWCTesterApi.link_setmaccmdtype(self, "UNCONFIRMED")

            # -------- DRAIN STALE UPLINKS BEFORE SENDING --------
            self.drain_uplinks()

            # -------- RESET_DEVICE: capture boot_before BEFORE send,
            #         then send and verify reboot via boot counter
            #         (handler calls exec_mac internally) --------
            if cmd == Command.RESET_DEVICE:
                uplink_payload, result = self.handle_reset_response()
                self.log_to_csv(command_name, payload_hex, uplink_payload, result)
                print("Waiting 15 seconds before next payload...\n")
                time.sleep(15)
                continue

            # -------- SEND MAC --------
            self.exec_mac()

            # -------- REJOIN: route to specialized multi-stage handler --------
            if cmd == Command.REJOIN:
                delay_secs = int(data, 16)
                uplink_payload, result = self.handle_rejoin_response(payload_hex, delay_secs)
                self.log_to_csv(command_name, payload_hex, uplink_payload, result)
                print("Waiting 15 seconds before next payload...\n")
                time.sleep(15)
                continue

            print("Waiting for DataDown / DataUp...")

            uplink_payload = ""
            got_uplink = False
            timeout = time.time() + 60

            while time.time() < timeout:
                msg = RWCTesterApi.link_readmsg(self)

                if not msg or msg == "NA":
                    time.sleep(1)
                    continue

                self.cache_boot_if_port1(msg)

                if "DataUp" in str(msg):
                    # Port filter: only accept port 3 (downlink response port)
                    fport = self.extract_fport(msg)
                    if fport != 3:
                        print(f"Ignoring uplink on port {fport} (waiting for port 3)")
                        continue

                    parsed_payload = self.parse_uplink_payload(msg)
                    if not parsed_payload:
                        print("Unable to parse FRMPayload; continuing to wait")
                        continue

                    # Tag verification: response 2nd byte must match sent tag
                    fp_bytes = parsed_payload.split()
                    tag_got = fp_bytes[1].upper() if len(fp_bytes) >= 2 else "?"
                    if tag_got != expected_tag:
                        print(f"Ignoring stale port-3 response (tag={tag_got}, expected={expected_tag})")
                        continue

                    print("Parsed FRMPayload:", parsed_payload)
                    uplink_payload = parsed_payload
                    got_uplink = True
                    break

                time.sleep(1)

            # -------- HANDLE NO UPLINK --------
            if not got_uplink:
                print("WARNING: No uplink received for payload", payload_hex)
                uplink_payload = "NO_UPLINK"

            # -------- DECODE RESULT AND LOG --------
            result = self.decode_result(uplink_payload)
            self.log_to_csv(
                command_name,
                payload_hex,
                uplink_payload,
                result
            )

            # -------- REST BEFORE NEXT PAYLOAD --------
            print("Waiting 15 seconds before next payload...\n")
            time.sleep(15)

    # --------------------------------------------------------------

    def exec_link(self):
        """
        Function: exec_link

        Description:
            Initiates execution of the Link Analyzer test
            session on the RWC tester.

        Returns:
            None
        """
        print('Executing Link Analyzer Test')
        time.sleep(1)
        result = RWCTesterApi.link_run(self)
        print(result)

    def exec_mac(self):
        """
        Function: exec_mac

        Description:
            Forces transmission of the configured MAC
            command payload from the tester.

        Returns:
            None
        """
        print('Executing MAC Command (force send)')
        time.sleep(0.5)
        result = RWCTesterApi.link_sendmac(self)
        print(result)

    def read_link_messages(self):
        """
        Function: read_link_messages

        Description:
            Reads Link Analyzer messages from the tester
            and prints received data to the console.

        Returns:
            str: Received message
        """
        time.sleep(1)
        msg = RWCTesterApi.link_readmsg(self)
        print("link_readmsg ->", msg)
        return msg

    def stop_link(self):
        """
        Function: stop_link

        Description:
            Stops the active Link Analyzer test session.

        Returns:
            None
        """
        print('Stop Link Analyzer Test')
        result = RWCTesterApi.link_stop(self)
        print(result)

    def close(self):
        """
        Function: close

        Description:
            Closes the communication port connection
            with the RWC tester.

        Returns:
            None
        """
        RWCTesterApi.close_port(self)
        print("port closed\n")
    
    def decode_result(self, frmpayload):
        """
        Function: decode_result

        Description:
            Decodes the DlStatus_t error byte (FRMPayload index 2)
            into a human-readable status string. Mirrors the enum
            in Model4811_Downlink.h.

            Sentinel inputs ("NO_UPLINK", "PARSE_FAILED") are passed
            through unchanged.

        Parameters:
            frmpayload (str): Parsed FRMPayload as space-separated
                              hex bytes, or a sentinel string.

        Returns:
            str: Decoded status (SUCCESS, dlstNoResources,
                 dlstTooShort, dlstInvalid, UNKNOWN_ERR_0xXX,
                 UNKNOWN_FORMAT, or pass-through sentinel)
        """
        sentinels = ("NO_UPLINK", "PARSE_FAILED")
        if frmpayload in sentinels:
            return frmpayload

        # Status byte unifies two encoding spaces:
        #   0x00         success (both paths)
        #   0x01..0x0B   Modbus exception codes (READ/WRITE complete)
        #   0x10..0x12   DlStatus_t (early-exit failures)
        #   0x80..0xFF   int8 negative internal errors (firmware-clamped)
        err_map = {
            "00": "SUCCESS",
            # Modbus exception codes (forwarded from WattNode by
            # doDlrqRead_complete / doDlrqWrite_complete)
            "01": "MODBUS_ILLEGAL_FUNCTION",
            "02": "MODBUS_ILLEGAL_DATA_ADDRESS",
            "03": "MODBUS_ILLEGAL_DATA_VALUE",
            "04": "MODBUS_SLAVE_DEVICE_FAILURE",
            "05": "MODBUS_ACKNOWLEDGE",
            "06": "MODBUS_SLAVE_DEVICE_BUSY",
            "08": "MODBUS_MEMORY_PARITY_ERROR",
            "0A": "MODBUS_GATEWAY_PATH_UNAVAILABLE",
            "0B": "MODBUS_GATEWAY_TARGET_FAILED",
            # DlStatus_t (firmware-level early-exit failures)
            "10": "dlstNoResources",
            "11": "dlstTooShort",
            "12": "dlstInvalid",
        }
        parts = frmpayload.split()
        if len(parts) < 3:
            return "UNKNOWN_FORMAT"
        err_byte = parts[2].upper()
        if err_byte in err_map:
            return err_map[err_byte]
        val = int(err_byte, 16)
        if val >= 0x80:
            return f"INTERNAL_ERR_{val - 0x100}"
        return f"UNKNOWN_ERR_0x{err_byte}"

    def log_to_csv(self, command, downlink, uplink, result):
        """
        Function: log_to_csv

        Description:
            Logs MAC command execution details into the CSV report file.
            Records the command name, transmitted downlink payload,
            received uplink payload, and decoded result for regression
            tracking and post-analysis.

        Parameters:
            command  (str): Human-readable command name
            downlink (str): Encoded downlink payload
            uplink   (str): Parsed uplink payload
            result   (str): Decoded status (SUCCESS, dlstTooShort,
                            REJOIN_OK, NO_UPLINK, etc.)

        Returns:
            None
        """
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([command, downlink, uplink, result])

if __name__ == '__main__':

    print("\n-------- RWC Link Analyzer Test Script --------\n")

    myobj = LinkAnalyzerTest('5001', '192.168.1.67')

    try:
        myobj.config_link_screen()
        myobj.config_protocol()
        myobj.config_rf()

        myobj.exec_link()
        myobj.config_mac()

        print("\n--- Link Analyzer Running ---")

        while True:
            myobj.read_link_messages()

    except KeyboardInterrupt:
        print("\nCTRL + C pressed by user")
        myobj.stop_link()

    finally:
        myobj.close()
