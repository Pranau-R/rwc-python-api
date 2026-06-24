import sys
import time
import os
import re
import csv

sys.path.insert(0, os.path.abspath('..'))
from rwclib.cRWC5020x import RWCTesterApi


class LinkAnalyzerTest(RWCTesterApi):

    def __init__(self, port, addr=None):
        RWCTesterApi.__init__(self, port, addr)
        RWCTesterApi.open_port(self)

        # ---- CSV setup (single file, append mode) ----
        self.csv_file = "rwc_mac_log_02.csv"

        # Write header ONLY if file does not exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["COMMAND", "DOWNLINK_PAYLOAD", "UPLINK_PAYLOAD"])

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
            writer.writerow(["------------- DOWNLINK COMMANDS -------------", "", ""])

    def decode_command_name(self, payload_hex):
        """
        Function: decode_command_name

        Description:
            Decodes a hex payload string into a human-readable
            command name (e.g. "WRITE ENERGY_POS2_I32"), matching
            the format used by the enum-driven builder in test_01.

        Parameters:
            payload_hex (str): Hexadecimal payload string

        Returns:
            str: Human-readable command name
        """
        cmd_map = {
            "00": "READ",         "01": "WRITE",
            "02": "RESET_DEVICE", "03": "GET_VERSION",
            "04": "RESET_APPEUI", "05": "REJOIN",
        }
        reg_map = {
            "0BB9": "ENERGY_POS1_I32",  "0BBB": "ENERGY_POS2_I32",
            "0BBD": "ENERGY_POS3_I32",  "0BBF": "ENERGY_NEG1_I32",
            "0BC1": "ENERGY_NEG2_I32",  "0BC3": "ENERGY_NEG3_I32",
            "0BC5": "DEMAND1_F32",      "0BC7": "DEMAND2_F32",
            "0BC9": "DEMAND3_F32",      "0BCB": "METERCONFIG1_I16",
            "0BCC": "METERCONFIG2_I16", "0BCD": "METERCONFIG3_I16",
        }
        cmd_byte = payload_hex[0:2].upper()
        cmd_name = cmd_map.get(cmd_byte, f"UNKNOWN_{cmd_byte}")
        if cmd_byte in ("00", "01") and len(payload_hex) >= 8:
            reg_hex = payload_hex[4:8].upper()
            reg_name = reg_map.get(reg_hex, f"REG_{reg_hex}")
            return f"{cmd_name} {reg_name}"
        return cmd_name

    def log_to_csv(self, command, downlink, uplink):
        """
        Function: log_to_csv

        Description:
            Logs MAC command execution details into the CSV report file.
            Records the command name, transmitted downlink payload,
            and received uplink payload for regression tracking
            and post-analysis.

        Parameters:
            command  (str): Human-readable command name
            downlink (str): Encoded downlink payload
            uplink   (str): Parsed uplink payload

        Returns:
            None
        """
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([command, downlink, uplink])

    def config_link_screen(self):
        screenparamdict = {'testmode': 'EDT', 'submenu': 'LINK'}

        print('Setting up Test Mode to EDT')
        RWCTesterApi.set_mode(self, screenparamdict.get('testmode'))
        mymode = RWCTesterApi.query_mode(self)
        print('Test Mode: {}\n'.format(mymode))

        RWCTesterApi.set_screen(self, screenparamdict.get('submenu'))
        print("config_link_screen done\n")

    def config_protocol(self):
        print('Setting up PROTOCOL parameters')

        DEV_EUI_HEX = "0002CC0200992301"
        APP_EUI_HEX = "0000000000000004"
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
        hex_str = hex_str.replace(" ", "")
        payload_bytes = bytes.fromhex(hex_str)
        payload_int = int.from_bytes(payload_bytes, "big")
        payload_size = len(payload_bytes)
        return payload_int, payload_size

    def parse_uplink_payload(self, msg):
        """
        Extract FRMPayload from DataUp log string safely
        (handles hidden NULL characters in RWC output).
        """

        try:
            # Extract everything after timestamp ]
            if "]" not in msg:
                print("No timestamp found in message")
                return None

            hex_part = msg.split("]")[1]

            # Extract only valid HEX byte pairs using regex
            # This avoids problems with \x00 and hidden characters
            hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", hex_part)

            if len(hex_bytes) < 13:
                print("Frame too short to parse payload:", hex_bytes)
                return None

            # Convert hex strings to integers
            frame = [int(b, 16) for b in hex_bytes]

            # LoRaWAN fixed lengths
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
                print("⚠ No FRMPayload present in frame")
                return None

            payload_bytes = frame[payload_start:payload_end]

            # Convert payload to HEX string
            payload_hex = " ".join(f"{b:02X}" for b in payload_bytes)

            return payload_hex

        except Exception as e:
            print("Failed to parse uplink payload:", e)
            return None

    def config_mac(self):
        FPORT = 3
        # 🔹 Mark start of new test cycle in CSV
        self.log_new_cycle()

        payloads = {
            1: "0301",
            2: "01020BBB000E000A",
            3: "00030BBB02",
            4: "01040BBD000B000C",
            5: "00050BBD02",
            6: "01060BBF000D000E",
            7: "00070BBF02",
            8: "01080BC1000F0010",
            9: "00090BC102"
        }

        RWCTesterApi.link_setnumofmaccmd(self, 1)

        for key, payload_hex in payloads.items():
            payload_int, payload_size = self.hex_payload_to_int_and_size(payload_hex)

            print("\n--------------------------------------------")
            print(f"Sending MAC Payload: 0x{payload_hex}")

            RWCTesterApi.link_setinstantmaccmd(self, 1, "USER_DEFINED")
            print("MAC TYPE:", RWCTesterApi.link_getinstantmaccmd(self, 1))

            RWCTesterApi.link_setfport(self, FPORT)
            print("FPORT:", RWCTesterApi.link_getfport(self))

            RWCTesterApi.link_setpayloadsize(self, payload_size)
            print("SIZE:", RWCTesterApi.link_getpayloadsize(self))

            RWCTesterApi.link_setpayload(self, payload_int, payload_size)
            print("PAYLOAD:", RWCTesterApi.link_getpayload(self))

            RWCTesterApi.link_setmaccmdtype(self, "UNCONFIRMED")

            # -------- SEND MAC --------
            self.exec_mac()

            print("Waiting for DataDown / DataUp...")

            uplink_payload = ""
            got_uplink = False
            timeout = time.time() + 30   # max 30 sec wait

            while time.time() < timeout:
                msg = RWCTesterApi.link_readmsg(self)

                if not msg or msg == "NA":
                    time.sleep(1)
                    continue

                # Print only useful packets
                if "DataDown" in str(msg) or "DataUp" in str(msg):
                    print(">>>", msg)

                if "DataUp" in str(msg):
                    parsed_payload = self.parse_uplink_payload(msg)

                    if parsed_payload:
                        print("Parsed FRMPayload:", parsed_payload)
                        uplink_payload = parsed_payload
                    else:
                        print("Unable to parse FRMPayload")
                        uplink_payload = "PARSE_FAILED"

                    got_uplink = True
                    break


                time.sleep(1)

            # -------- HANDLE NO UPLINK --------
            if not got_uplink:
                print("WARNING: No uplink received for payload", payload_hex)
                uplink_payload = "NO_UPLINK"

            # -------- CSV LOGGING --------
            command_name = self.decode_command_name(payload_hex)
            self.log_to_csv(command_name, payload_hex, uplink_payload)

            # -------- REST BEFORE NEXT PAYLOAD --------
            print("Waiting 15 seconds before next payload...\n")
            time.sleep(15)


    def exec_link(self):
        print('Executing Link Analyzer Test')
        time.sleep(1)
        result = RWCTesterApi.link_run(self)
        print(result)
        print("exec_link done\n")

    def exec_mac(self):
        print('Executing MAC Command (force send)')
        time.sleep(0.5)
        result = RWCTesterApi.link_sendmac(self)
        print(result)
        print("exec_mac done\n")

    def read_link_messages(self):
        time.sleep(1)
        msg = RWCTesterApi.link_readmsg(self)
        print("link_readmsg ->", msg)
        return msg

    def stop_link(self):
        print('Stop Link Analyzer Test')
        result = RWCTesterApi.link_stop(self)
        print(result)
        print("stop_link done\n")

    def close(self):
        RWCTesterApi.close_port(self)
        print("port closed\n")

if __name__ == '__main__':

    print("\n-------- RWC Link Analyzer Test Script --------\n")
    print("----------------- Version 3.0.0 -----------------\n")

    myobj = LinkAnalyzerTest('5001', '192.168.1.67')

    try:
        myobj.config_link_screen()
        myobj.config_protocol()
        myobj.config_rf()

        #  START LINK FIRST
        myobj.exec_link()

        #  SEND PAYLOADS SEQUENTIALLY
        myobj.config_mac()

        print("\n--- Link Analyzer Running ---")
        print("--- Listening for uplink messages (CTRL + C to stop) ---\n")

        while True:
            myobj.read_link_messages()

    except KeyboardInterrupt:
        print("\nCTRL + C pressed by user")
        print("Stopping Link Analyzer...")
        myobj.stop_link()

    finally:
        myobj.close()
