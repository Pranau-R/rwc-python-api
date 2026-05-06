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

        # ---- CSV setup (single file, append mode) ----
        self.csv_file = "rwc_mac_log.csv"

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
            # writer.writerow(["---- NEW TEST CYCLE ----", "", ""])
            writer.writerow(["------------- DOWNLINK COMMANDS -------------", "", ""])

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

            (Command.WRITE, Register.ENERGY_POS2_I32, "000E000A"),
            (Command.READ,  Register.ENERGY_POS2_I32, "02"),

            (Command.WRITE, Register.ENERGY_POS3_I32, "000B000C"),
            (Command.READ,  Register.ENERGY_POS3_I32, "02"),
            
            (Command.WRITE, Register.ENERGY_NEG1_I32, "000D"),
            (Command.READ,  Register.ENERGY_NEG1_I32, "01"),
            
            # (Command.WRITE, Register.METERCONFIG2_I16, "00FF"),
            # (Command.READ,  Register.METERCONFIG2_I16, "01"),
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

            print("\n--------------------------------------------")
            print(f"Sending MAC Payload: {command_name} -> 0x{payload_hex}")

            RWCTesterApi.link_setinstantmaccmd(self, 1, "USER_DEFINED")
            RWCTesterApi.link_setfport(self, FPORT)
            RWCTesterApi.link_setpayloadsize(self, payload_size)
            RWCTesterApi.link_setpayload(self, payload_int, payload_size)
            RWCTesterApi.link_setmaccmdtype(self, "UNCONFIRMED")

            # -------- SEND MAC --------
            self.exec_mac()
            print("Waiting for DataDown / DataUp...")

            uplink_payload = ""
            got_uplink = False
            timeout = time.time() + 30

            while time.time() < timeout:
                msg = RWCTesterApi.link_readmsg(self)

                if not msg or msg == "NA":
                    time.sleep(1)
                    continue

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
            self.log_to_csv(
                command_name,
                payload_hex,
                uplink_payload
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
