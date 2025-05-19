#!/usr/bin/env python3

import time
import sys
import logging
import csv
import os
from ctypes import c_void_p, cast, POINTER, c_char_p, sizeof, string_at

# --- SDK Import Block ---
try:
    from NetSDK.NetSDK import NetClient
    from NetSDK.SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE, \
                                EM_VEHICLE_DIRECTION, EM_TRAFFICCAR_CAR_TYPE, EM_SNAPCATEGORY # These are the class names
    from NetSDK.SDK_Struct import NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY, \
                                  DEV_EVENT_TRAFFICJUNCTION_INFO, NET_A_DEV_EVENT_TRAFFICGATE_INFO, \
                                  NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO, NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO, \
                                  DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO, NET_TIME_EX, SDK_MSG_OBJECT, \
                                  SDK_RECT, EVENT_COMM_INFO, NET_TRAFFICCAR_BLACK_LIST, NET_TRAFFICCAR_WHITE_LIST
    from NetSDK.SDK_Callback import fDisConnect, fHaveReConnect, fAnalyzerDataCallBack
except ImportError as e:
    print(f"CRITICAL: Failed to import Dahua NetSDK modules. Check SDK_Struct.py and SDK_Enum.py for correct names: {e}")
    sys.exit(1)
except Exception as e:
    print(f"CRITICAL: Unexpected error during SDK import: {e}")
    sys.exit(1)
# --- End SDK Import Block ---

# --- Configuration ---
CAMERA_IP = "10.45.14.11"
CAMERA_PORT = 37777
USERNAME = "admin"
PASSWORD = "%Gq65FUS8842G"
CHANNEL_ID = 0
ANPR_EVENT_TYPE = EM_EVENT_IVS_TYPE.ALL
LOG_FILE = "anpr_events.log"
CSV_FILE = "anpr_records_sdk.csv" # New CSV filename
CSV_HEADERS = [
    "Blocklist", "VehicleType", "PlateColor", "PlateNo", "PlateSize", "Allowlist",
    "SnapshotSource", "SubscribedPlatformIP", "Time", "VehicleColor",
    "VehicleFrontOrBack", "VehicleLogo", "SDKEventType", "ImageSize"
]

# --- Global Variables & Logging Setup ---
g_sdk, g_login_id, g_analyzer_handle = None, 0, 0
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s')
file_handler, console_handler = logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)
file_handler.setFormatter(log_formatter); file_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter); console_handler.setLevel(logging.INFO)
logger = logging.getLogger(); logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler); logger.addHandler(console_handler)

# --- Enum Mappings (Based on ACTUAL runtime diagnostics) ---
# Using integer keys as the enum members were different than expected.
# These string values are now best guesses or match your GUI CSV example.

VEHICLE_TYPE_MAP = {
    0: "Unknown Vehicle", # from runtime EM_TRAFFICCAR_CAR_TYPE.UNKNOWN
    1: "Trust Car",       # from runtime EM_TRAFFICCAR_CAR_TYPE.TRUST_CAR
    2: "Suspicious Car",  # from runtime EM_TRAFFICCAR_CAR_TYPE.SUSPICIOUS_CAR
    3: "Normal Car",      # from runtime EM_TRAFFICCAR_CAR_TYPE.NORMAL_CAR. Your log shows "EnumVal:3", and GUI had "Light Truck".
                          # This is a mismatch. The camera might send '3' for Light Truck via stTrafficCar.emCarType,
                          # but the SDK's EM_TRAFFICCAR_CAR_TYPE has '3' as NORMAL_CAR.
                          # We will prioritize stTrafficCar.szCategory for vehicle type string if available.
    18: "Light Truck"     # Added this to map the value if camera still sends '18' despite limited enum
}

VEHICLE_DIRECTION_MAP = {
    0: "Unknown Direction", # from runtime EM_VEHICLE_DIRECTION.UNKOWN (note spelling)
    1: "Vehicle Front",     # from runtime EM_VEHICLE_DIRECTION.HEAD
    2: "Vehicle Back",      # from runtime EM_VEHICLE_DIRECTION.TAIL
    3: "Vehicle Bodyside"   # from runtime EM_VEHICLE_DIRECTION.VEHBODYSIDE
}

# EM_SNAPCATEGORY seems corrupted or misidentified in the runtime SDK_Enum.py
# It showed MOTOR: 0, NONMOTOR: 1. This is not for snap categories.
# We will rely on dwSnapFlagMask for SnapshotSource or leave it generic.
SNAPSHOT_SOURCE_MAP = {
    # Based on dwSnapFlagMask bits rather than the problematic EM_SNAPCATEGORY
    # Bit 1 (value 2): Timing (if using 1-based indexing for bits, or value for bit itself)
    # Bit 2 (value 4): Manual
    # Bit 4 (value 16): Event
    # Mapping these as integers for now. This needs careful checking with actual dwSnapFlagMask values.
    "Timing_Flag": "Timing",
    "Manual_Flag": "Manual",
    "Event_Flag": "Video", # To match your GUI export
    "Unknown_Flag": "Unknown Source"
}
# --- End Enum Mappings ---


# --- CSV Handling (initialize_csv, append_to_csv - same as before) ---
def initialize_csv():
    file_exists = os.path.isfile(CSV_FILE)
    is_empty = False
    if file_exists: is_empty = os.path.getsize(CSV_FILE) == 0
    if not file_exists or is_empty:
        try:
            with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as csvfile:
                csv.writer(csvfile).writerow(CSV_HEADERS)
            logger.info(f"CSV file '{CSV_FILE}' initialized with headers.")
        except IOError as e: logger.error(f"Error initializing CSV: {e}")

def append_to_csv(data_row):
    try:
        with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as csvfile:
            csv.writer(csvfile).writerow(data_row)
    except IOError as e: logger.error(f"Error writing to CSV: {e}")

# --- Callback Functions (DisconnectCallback, ReconnectCallback - same as before) ---
@fDisConnect
def DisconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown"
    logger.warning(f"DISCONNECTED - ID:{lLoginID}, IP:{ip}:{nDVRPort}\n")

@fHaveReConnect
def ReconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown"
    logger.info(f"RECONNECTED - ID:{lLoginID}, IP:{ip}:{nDVRPort}\n")

@fAnalyzerDataCallBack
def AnalyzerDataCallback(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    logger.info(f"Event Received - Handle:{lAnalyzerHandle}, AlarmType:{dwAlarmType}({hex(dwAlarmType)}), Seq:{nSequence}")

    csv_data = {header: "" for header in CSV_HEADERS}
    csv_data["SDKEventType"] = f"SDKEventType({dwAlarmType})"
    csv_data["SubscribedPlatformIP"] = "" # Cannot get this from SDK event
    csv_data["ImageSize"] = dwBufSize if pBuffer and dwBufSize > 0 else 0
    
    event_struct_map = {
        EM_EVENT_IVS_TYPE.TRAFFICJUNCTION: ("TRAFFICJUNCTION", DEV_EVENT_TRAFFICJUNCTION_INFO),
        EM_EVENT_IVS_TYPE.TRAFFICGATE: ("TRAFFICGATE", NET_A_DEV_EVENT_TRAFFICGATE_INFO),
        EM_EVENT_IVS_TYPE.TRAFFIC_MANUALSNAP: ("TRAFFIC_MANUALSNAP", NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO),
    }

    if dwAlarmType in event_struct_map:
        event_name_for_log, StructType = event_struct_map[dwAlarmType]
        csv_data["EventType"] = event_name_for_log

        try:
            event_info = cast(pAlarmInfo, POINTER(StructType)).contents

            if hasattr(event_info, 'UTC') and isinstance(event_info.UTC, NET_TIME_EX):
                utc = event_info.UTC
                csv_data["Time"] = f"{utc.dwYear:04d}-{utc.dwMonth:02d}-{utc.dwDay:02d} {utc.dwHour:02d}:{utc.dwMinute:02d}:{utc.dwSecond:02d}"

            if hasattr(event_info, 'stTrafficCar') and isinstance(event_info.stTrafficCar, DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO):
                traffic_car = event_info.stTrafficCar
                if hasattr(traffic_car, 'szPlateNumber'):
                    csv_data["PlateNo"] = traffic_car.szPlateNumber.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szPlateColor'):
                    csv_data["PlateColor"] = traffic_car.szPlateColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szVehicleColor'):
                    csv_data["VehicleColor"] = traffic_car.szVehicleColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                
                vehicle_type_category_str = ""
                if hasattr(traffic_car, 'szCategory'):
                    vehicle_type_category_str = traffic_car.szCategory.decode('utf-8', errors='ignore').strip('\x00').strip()
                
                if vehicle_type_category_str: # Prefer szCategory for vehicle type string
                    csv_data["VehicleType"] = vehicle_type_category_str
                elif hasattr(traffic_car, 'emCarType'): # Fallback to our integer-keyed map
                    csv_data["VehicleType"] = VEHICLE_TYPE_MAP.get(traffic_car.emCarType, f"EnumVal:{traffic_car.emCarType}")

                if hasattr(traffic_car, 'szVehicleSign'):
                    csv_data["VehicleLogo"] = traffic_car.szVehicleSign.decode('utf-8', errors='ignore').strip('\x00').strip()
                
                if hasattr(traffic_car, 'stuBlackList') and hasattr(traffic_car.stuBlackList, 'bIsBlackCar'):
                    csv_data["Blocklist"] = "Yes" if traffic_car.stuBlackList.bIsBlackCar == 1 else "No"
                
                if hasattr(traffic_car, 'stuWhiteList') and hasattr(traffic_car.stuWhiteList, 'bTrustCar'):
                    csv_data["Allowlist"] = "Yes" if traffic_car.stuWhiteList.bTrustCar == 1 else "No"
            
            if not csv_data["PlateNo"] and hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'szText'):
                plate_cand = event_info.stuObject.szText.decode('utf-8', errors='ignore').strip('\x00').strip()
                if plate_cand: csv_data["PlateNo"] = plate_cand

            if hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'BoundingBox'):
                bbox = event_info.stuObject.BoundingBox
                if all(hasattr(bbox, attr) for attr in ['left', 'top', 'right', 'bottom']):
                    width = bbox.right - bbox.left
                    height = bbox.bottom - bbox.top
                    if width > 0 and height > 0:
                         csv_data["PlateSize"] = f"{width}*{height}"

            if hasattr(event_info, 'byVehicleDirection'):
                csv_data["VehicleFrontOrBack"] = VEHICLE_DIRECTION_MAP.get(event_info.byVehicleDirection, f"EnumVal:{event_info.byVehicleDirection}")

            # SnapshotSource: Relying on dwSnapFlagMask primarily due to EM_SNAPCATEGORY issues
            if hasattr(event_info, 'dwSnapFlagMask'):
                snap_mask = event_info.dwSnapFlagMask
                if snap_mask & (1 << 4): # Bit 4: Event (Matches GUI "Video")
                    csv_data["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get("Event_Flag", "EventTrigger_Flag")
                elif snap_mask & (1 << 2): # Bit 2: Manual
                    csv_data["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get("Manual_Flag", "Manual_Flag")
                elif snap_mask & (1 << 1): # Bit 1: Timing
                    csv_data["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get("Timing_Flag", "Timing_Flag")
                else:
                    csv_data["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get("Unknown_Flag", f"SDKFlagMask({snap_mask})")
            elif hasattr(event_info, 'stCommInfo') and hasattr(event_info.stCommInfo, 'emSnapCategory'):
                 # Fallback if dwSnapFlagMask isn't definitive, but EM_SNAPCATEGORY is problematic
                 logger.warning(f"Using stCommInfo.emSnapCategory which might be unreliable: {event_info.stCommInfo.emSnapCategory}")
                 # If EM_SNAPCATEGORY was reliable, you'd use:
                 # csv_data["SnapshotSource"] = YOUR_RELIABLE_SNAPCATEGORY_MAP.get(event_info.stCommInfo.emSnapCategory, f"SnapCatEnum:{event_info.stCommInfo.emSnapCategory}")
                 csv_data["SnapshotSource"] = f"SnapCatEnumVal:{event_info.stCommInfo.emSnapCategory}"


            logger.info(f"  Extracted for CSV ({event_name_for_log}): { {k:v for k,v in csv_data.items() if k not in ['SDKEventType', 'SubscribedPlatformIP']} }")

            if csv_data["PlateNo"] and csv_data["PlateNo"] != "":
                row_to_write = [csv_data.get(h, "") for h in CSV_HEADERS]
                append_to_csv(row_to_write)

        except Exception as e:
            logger.error(f"  Error processing {event_name_for_log} for CSV: {e}", exc_info=True)

    elif dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICSNAPSHOT:
        csv_data["EventType"] = "TRAFFICSNAPSHOT (Aggregate)"
        logger.info(f"  Event Type: TRAFFICSNAPSHOT. Aggregate event. Details per sub-capture not implemented for CSV here.")
    else:
        logger.info(f"  Event Type {csv_data['SDKEventType']} not listed for detailed ANPR CSV export.")

    logger.info(f"----------------------------------\n")

# --- Main Application Logic (same as before) ---
def main():
    global g_sdk, g_login_id, g_analyzer_handle
    initialize_csv()
    logger.info("Initializing Dahua NetSDK...")
    g_sdk = NetClient()
    init_success = g_sdk.InitEx(DisconnectCallback)
    if not init_success: logger.error("Failed to initialize NetSDK."); return
    logger.info("SDK Initialized."); g_sdk.SetAutoReconnect(ReconnectCallback)
    logger.info("Auto-reconnect set.")
    logger.info(f"Logging into camera: {CAMERA_IP}:{CAMERA_PORT}")
    login_req = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_req.dwSize = sizeof(login_req); login_req.szIP = CAMERA_IP.encode('utf-8')
    login_req.nPort = CAMERA_PORT; login_req.szUserName = USERNAME.encode('utf-8')
    login_req.szPassword = PASSWORD.encode('utf-8'); login_req.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP
    login_res = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY(); login_res.dwSize = sizeof(login_res)
    login_result_tuple = g_sdk.LoginWithHighLevelSecurity(login_req, login_res)
    if isinstance(login_result_tuple, tuple) and len(login_result_tuple) == 3:
        g_login_id, error_msg_str = login_result_tuple[0], login_result_tuple[2]
    else:
        logger.error(f"Login result format error: {login_result_tuple}")
        g_login_id, error_msg_str = 0, "SDK Login format error."
    if g_login_id == 0:
        logger.error(f"Login Failed. SDK Msg: '{error_msg_str}'.")
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup(); return
    logger.info(f"Login OK. ID: {g_login_id}")
    logger.info(f"Subscribing to ALL IVS (Type: {ANPR_EVENT_TYPE}, Chan: {CHANNEL_ID})...")
    g_analyzer_handle = g_sdk.RealLoadPictureEx(g_login_id, CHANNEL_ID, ANPR_EVENT_TYPE, 1, AnalyzerDataCallback, 0, None)
    if g_analyzer_handle == 0:
        logger.error(f"Subscription failed (RealLoadPictureEx returned 0).")
        if hasattr(g_sdk, 'Logout'): g_sdk.Logout(g_login_id)
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup(); return
    logger.info(f"Subscribed OK. Handle: {g_analyzer_handle}. Waiting... Ctrl+C to exit.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: logger.info("\nCtrl+C. Exiting...")
    except Exception as e: logger.error(f"\nMain loop error: {e}", exc_info=True)
    finally:
        if g_analyzer_handle and g_sdk and hasattr(g_sdk, 'StopLoadPic'):
            logger.info(f"Stopping subscription (Handle: {g_analyzer_handle})...")
            res_stop = g_sdk.StopLoadPic(g_analyzer_handle); g_analyzer_handle = 0
            logger.info(f"Subscription stopped " + ("OK." if res_stop else "FAIL."))
        if g_login_id and g_sdk and hasattr(g_sdk, 'Logout'):
            logger.info(f"Logging out (ID: {g_login_id})...")
            res_logout = g_sdk.Logout(g_login_id); g_login_id = 0
            logger.info(f"Logout " + ("OK." if res_logout else "FAIL."))
        if g_sdk and hasattr(g_sdk, 'Cleanup'):
            logger.info("Cleaning SDK..."); g_sdk.Cleanup(); g_sdk = None
            logger.info("SDK Cleanup OK.")
        logging.shutdown()

if __name__ == "__main__":
    main()
