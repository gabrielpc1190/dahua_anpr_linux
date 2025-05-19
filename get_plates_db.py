#!/usr/bin/env python3

import time
import sys
import logging
import csv
import os
import sqlite3
from ctypes import c_void_p, cast, POINTER, c_char_p, sizeof, string_at
import re

# --- SDK Import Block ---
try:
    from NetSDK.NetSDK import NetClient
    from NetSDK.SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE, \
                                EM_VEHICLE_DIRECTION, EM_TRAFFICCAR_CAR_TYPE, EM_SNAPCATEGORY
    from NetSDK.SDK_Struct import NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY, \
                                  DEV_EVENT_TRAFFICJUNCTION_INFO, NET_A_DEV_EVENT_TRAFFICGATE_INFO, \
                                  NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO, NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO, \
                                  DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO, NET_TIME_EX, SDK_MSG_OBJECT, \
                                  SDK_RECT, EVENT_COMM_INFO, NET_TRAFFICCAR_BLACK_LIST, NET_TRAFFICCAR_WHITE_LIST
    from NetSDK.SDK_Callback import fDisConnect, fHaveReConnect, fAnalyzerDataCallBack
except ImportError as e:
    print(f"CRITICAL: Failed to import Dahua NetSDK modules: {e}")
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
CSV_FILE = "anpr_records_sdk_final_v3.csv" # Incrementing version for clarity
IMAGE_DIR = "anpr_images"
DB_FILE = "anpr_data.db"

CSV_HEADERS = [
    "Blocklist", "VehicleType", "PlateColor", "PlateNo", "PlateSize", "Allowlist",
    "SnapshotSource", "SubscribedPlatformIP", "Time", "VehicleColor",
    "VehicleFrontOrBack", "VehicleLogo", "SDKEventType", "ImageSize", "ImageFilename"
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

# --- Enum Mappings (Based on ACTUAL runtime diagnostics and SDK_Enum.py) ---
VEHICLE_TYPE_MAP = { # Using integer keys from the ACTUAL EM_TRAFFICCAR_CAR_TYPE at runtime
    0: "Unknown Vehicle",    # Actual Runtime: UNKNOWN
    1: "Trust Car",          # Actual Runtime: TRUST_CAR
    2: "Suspicious Car",     # Actual Runtime: SUSPICIOUS_CAR
    3: "Normal Car",         # Actual Runtime: NORMAL_CAR
    # Add specific values if camera sends them despite the limited runtime enum, e.g. for stTrafficCar.emCarType
    EM_TRAFFICCAR_CAR_TYPE.LIGHTTRUCK: "Light Truck", # Using imported enum member if available
    EM_TRAFFICCAR_CAR_TYPE.MOTORCYCLE: "Motorcycle",
    EM_TRAFFICCAR_CAR_TYPE.SALOONCAR: "SaloonCar",
    EM_TRAFFICCAR_CAR_TYPE.SUVMPV: "SUV", # Matching your log for SUV
    EM_TRAFFICCAR_CAR_TYPE.PICKUP: "Pickup",
    EM_TRAFFICCAR_CAR_TYPE.MICROTRUCK: "MicroTruck",

}

VEHICLE_DIRECTION_MAP = { # Using integer keys from ACTUAL EM_VEHICLE_DIRECTION at runtime
    0: "Unknown Direction", # Actual Runtime: UNKOWN (with O)
    1: "Vehicle Front",     # Actual Runtime: HEAD
    2: "Vehicle Back",      # Actual Runtime: TAIL
    3: "Vehicle Bodyside"   # Actual Runtime: VEHBODYSIDE
}

SNAPSHOT_SOURCE_MAP = { # Using integer keys from ACTUAL EM_SNAPCATEGORY
    EM_SNAPCATEGORY.UNKNOWN: "Unknown",       # 0
    EM_SNAPCATEGORY.TIMING: "Timing",         # 1 (This is what your log "SnapCatEnum:1" means)
    EM_SNAPCATEGORY.MANUAL: "Manual",         # 2
    EM_SNAPCATEGORY.TRIGGER: "Ext. Trigger",  # 3
    EM_SNAPCATEGORY.LOCALTRIGGER: "Local Trig.",# 4
    EM_SNAPCATEGORY.EVENT: "Video Event",     # 5 (This should match GUI "Video")
    EM_SNAPCATEGORY.BROKENNET: "NetResend"    # 6
}
# --- End Enum Mappings ---

# --- File/Directory Helper & CSV Handling (ensure_dir, sanitize_filename, initialize_csv, append_to_csv - same as before) ---
def ensure_dir(directory_path):
    if not os.path.exists(directory_path):
        try: os.makedirs(directory_path); logger.info(f"Created directory: {directory_path}")
        except OSError as e: logger.error(f"Error creating directory {directory_path}: {e}"); return False
    return True

def sanitize_filename(name_part):
    if not name_part or name_part == "N/A": return "NO_PLATE"
    return re.sub(r'[\\/*?:"<>|]', "_", name_part)

def initialize_csv():
    # ... (same as before)
    file_exists = os.path.isfile(CSV_FILE)
    is_empty = False
    if file_exists: is_empty = os.path.getsize(CSV_FILE) == 0
    if not file_exists or is_empty:
        try:
            with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as csvfile:
                csv.writer(csvfile).writerow(CSV_HEADERS)
            logger.info(f"CSV file '{CSV_FILE}' initialized with headers.")
        except IOError as e: logger.error(f"Error initializing CSV: {e}")

def append_to_csv(data_dict):
    # ... (same as before)
    try:
        row_to_write = [data_dict.get(h, "") for h in CSV_HEADERS]
        with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as csvfile:
            csv.writer(csvfile).writerow(row_to_write)
    except IOError as e: logger.error(f"Error writing to CSV: {e}")

# --- SQLite Database Handling (DB_CONNECTION, initialize_database, insert_anpr_event_db - same as before) ---
DB_CONNECTION = None
def initialize_database():
    # ... (same as before)
    global DB_CONNECTION
    try:
        DB_CONNECTION = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = DB_CONNECTION.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anpr_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, Timestamp TEXT, PlateNumber TEXT,
                SDKEventTypeRaw INTEGER, EventType TEXT, PlateColor TEXT, VehicleColor TEXT,
                VehicleType TEXT, PlateSize TEXT, Blocklist TEXT, Allowlist TEXT, SnapshotSource TEXT,
                VehicleLogo TEXT, VehicleFrontOrBack TEXT, ImageSize INTEGER, ImageFilename TEXT,
                ReceivedAt TEXT DEFAULT CURRENT_TIMESTAMP )
        ''')
        DB_CONNECTION.commit()
        logger.info(f"SQLite database '{DB_FILE}' initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing SQLite database: {e}")
        DB_CONNECTION = None

def insert_anpr_event_db(event_data_dict):
    # ... (same as before, ensure keys match `event_data_for_export` and DB columns)
    if DB_CONNECTION is None: logger.error("DB connection NA."); return
    sql = '''
        INSERT INTO anpr_events ( Timestamp, PlateNumber, SDKEventTypeRaw, EventType, PlateColor, VehicleColor, VehicleType,
            PlateSize, Blocklist, Allowlist, SnapshotSource, VehicleLogo, VehicleFrontOrBack, ImageSize, ImageFilename
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
    try:
        cursor = DB_CONNECTION.cursor()
        raw_sdk_event_type = 0 # Default
        sdk_event_type_str = event_data_dict.get("SDKEventType", "(0)")
        match = re.search(r'\((\d+)\)', sdk_event_type_str)
        if match: raw_sdk_event_type = int(match.group(1))

        data_tuple = (
            event_data_dict.get("Time"), event_data_dict.get("PlateNo"), raw_sdk_event_type,
            event_data_dict.get("EventType"), event_data_dict.get("PlateColor"), event_data_dict.get("VehicleColor"),
            event_data_dict.get("VehicleType"), event_data_dict.get("PlateSize"), event_data_dict.get("Blocklist"),
            event_data_dict.get("Allowlist"), event_data_dict.get("SnapshotSource"), event_data_dict.get("VehicleLogo"),
            event_data_dict.get("VehicleFrontOrBack"), event_data_dict.get("ImageSize"), event_data_dict.get("ImageFilename")
        )
        cursor.execute(sql, data_tuple)
        DB_CONNECTION.commit()
        logger.debug(f"Event data inserted into DB: {event_data_dict.get('PlateNo')}")
    except sqlite3.Error as e:
        logger.error(f"Error inserting into DB: {e} - Data: {data_tuple if 'data_tuple' in locals() else 'N/A'}")
    except Exception as ex:
        logger.error(f"Generic error during DB insert prep: {ex} - Data: {event_data_dict}")

# --- Callback Functions (DisconnectCallback, ReconnectCallback - same) ---
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

    event_data_for_export = {header: "" for header in CSV_HEADERS}
    event_data_for_export["SDKEventType"] = f"SDKEventType({dwAlarmType})"
    event_data_for_export["SubscribedPlatformIP"] = ""
    event_data_for_export["ImageSize"] = dwBufSize if pBuffer and dwBufSize > 0 else 0
    
    event_struct_map = {
        EM_EVENT_IVS_TYPE.TRAFFICJUNCTION: ("TRAFFICJUNCTION", DEV_EVENT_TRAFFICJUNCTION_INFO),
        EM_EVENT_IVS_TYPE.TRAFFICGATE: ("TRAFFICGATE", NET_A_DEV_EVENT_TRAFFICGATE_INFO),
        EM_EVENT_IVS_TYPE.TRAFFIC_MANUALSNAP: ("TRAFFIC_MANUALSNAP", NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO),
    }

    current_event_timestamp_for_filename = time.strftime("%Y%m%d_%H%M%S")

    if dwAlarmType in event_struct_map:
        event_name_for_log, StructType = event_struct_map[dwAlarmType]
        event_data_for_export["EventType"] = event_name_for_log

        try:
            event_info = cast(pAlarmInfo, POINTER(StructType)).contents

            if hasattr(event_info, 'UTC') and isinstance(event_info.UTC, NET_TIME_EX):
                utc = event_info.UTC
                event_data_for_export["Time"] = f"{utc.dwYear:04d}-{utc.dwMonth:02d}-{utc.dwDay:02d} {utc.dwHour:02d}:{utc.dwMinute:02d}:{utc.dwSecond:02d}"
                current_event_timestamp_for_filename = f"{utc.dwYear:04d}{utc.dwMonth:02d}{utc.dwDay:02d}_{utc.dwHour:02d}{utc.dwMinute:02d}{utc.dwSecond:02d}"
                if hasattr(utc, 'dwMillisecond'): current_event_timestamp_for_filename += f"_{utc.dwMillisecond:03d}"

            if hasattr(event_info, 'stTrafficCar') and isinstance(event_info.stTrafficCar, DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO):
                traffic_car = event_info.stTrafficCar
                if hasattr(traffic_car, 'szPlateNumber'):
                    event_data_for_export["PlateNo"] = traffic_car.szPlateNumber.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szPlateColor'):
                    event_data_for_export["PlateColor"] = traffic_car.szPlateColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szVehicleColor'):
                    event_data_for_export["VehicleColor"] = traffic_car.szVehicleColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                
                vehicle_type_category_str = ""
                if hasattr(traffic_car, 'szCategory'):
                    vehicle_type_category_str = traffic_car.szCategory.decode('utf-8', errors='ignore').strip('\x00').strip()
                if vehicle_type_category_str: event_data_for_export["VehicleType"] = vehicle_type_category_str
                elif hasattr(traffic_car, 'emCarType'): event_data_for_export["VehicleType"] = VEHICLE_TYPE_MAP.get(traffic_car.emCarType, f"EnumVal:{traffic_car.emCarType}")

                if hasattr(traffic_car, 'szVehicleSign'):
                    event_data_for_export["VehicleLogo"] = traffic_car.szVehicleSign.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'stuBlackList') and hasattr(traffic_car.stuBlackList, 'bIsBlackCar'):
                    event_data_for_export["Blocklist"] = "Yes" if traffic_car.stuBlackList.bIsBlackCar == 1 else "No"
                if hasattr(traffic_car, 'stuWhiteList') and hasattr(traffic_car.stuWhiteList, 'bTrustCar'):
                    event_data_for_export["Allowlist"] = "Yes" if traffic_car.stuWhiteList.bTrustCar == 1 else "No"
            
            if not event_data_for_export["PlateNo"] and hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'szText'):
                plate_cand = event_info.stuObject.szText.decode('utf-8', errors='ignore').strip('\x00').strip()
                if plate_cand: event_data_for_export["PlateNo"] = plate_cand

            if hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'BoundingBox'):
                bbox = event_info.stuObject.BoundingBox
                logger.info(f"    BoundingBox found: L={bbox.left}, T={bbox.top}, R={bbox.right}, B={bbox.bottom}")
                if all(hasattr(bbox, attr) for attr in ['left', 'top', 'right', 'bottom']):
                    width, height = bbox.right - bbox.left, bbox.bottom - bbox.top
                    if width > 0 and height > 0: event_data_for_export["PlateSize"] = f"{width}*{height}"
                    else: logger.warning(f"    BoundingBox dims invalid: W={width}, H={height}")
            else: logger.warning("    event_info.stuObject.BoundingBox not found.")

            if hasattr(event_info, 'byVehicleDirection'):
                event_data_for_export["VehicleFrontOrBack"] = VEHICLE_DIRECTION_MAP.get(event_info.byVehicleDirection, f"EnumVal:{event_info.byVehicleDirection}")

            # Updated SnapshotSource logic
            if hasattr(event_info, 'stCommInfo') and hasattr(event_info.stCommInfo, 'emSnapCategory'):
                # Use the integer value of the enum member for map lookup
                snap_category_val = event_info.stCommInfo.emSnapCategory
                event_data_for_export["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get(snap_category_val, f"SnapCatEnum:{snap_category_val}")
            elif hasattr(event_info, 'dwSnapFlagMask'): # Fallback
                snap_mask = event_info.dwSnapFlagMask
                if snap_mask & (1 << 4): event_data_for_export["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get(EM_SNAPCATEGORY.EVENT.value, "EventTrigger_Flag") # Use .value for IntEnum
                elif snap_mask & (1 << 2): event_data_for_export["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get(EM_SNAPCATEGORY.MANUAL.value, "Manual_Flag")
                elif snap_mask & (1 << 1): event_data_for_export["SnapshotSource"] = SNAPSHOT_SOURCE_MAP.get(EM_SNAPCATEGORY.TIMING.value, "Timing_Flag")
                else: event_data_for_export["SnapshotSource"] = f"SDKFlagMask({snap_mask})"
            
            if pBuffer and dwBufSize > 0:
                if ensure_dir(IMAGE_DIR):
                    plate_fn = sanitize_filename(event_data_for_export.get("PlateNo", "NO_PLATE"))
                    img_fn = f"{IMAGE_DIR}/{current_event_timestamp_for_filename}_{plate_fn}_{event_name_for_log}.jpg"
                    try:
                        img_bytes = string_at(pBuffer, dwBufSize)
                        with open(img_fn, "wb") as f_img: f_img.write(img_bytes)
                        logger.info(f"    Image saved: {img_fn}")
                        event_data_for_export["ImageFilename"] = img_fn # Relative path
                    except IOError as img_e:
                        logger.error(f"    Error saving image {img_fn}: {img_e}")
                        event_data_for_export["ImageFilename"] = "SAVE_ERROR"
            else: logger.info(f"    No image data in this event.")
            
            logger.info(f"  Extracted for Export ({event_name_for_log}): { {k:v for k,v in event_data_for_export.items() if k not in ['SDKEventType', 'SubscribedPlatformIP']} }")

            if event_data_for_export["PlateNo"] and event_data_for_export["PlateNo"] != "":
                append_to_csv(event_data_for_export)
                insert_anpr_event_db(event_data_for_export)

        except Exception as e:
            logger.error(f"  Error processing {event_name_for_log} for export: {e}", exc_info=True)

    elif dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICSNAPSHOT:
        event_data_for_export["EventType"] = "TRAFFICSNAPSHOT (Aggregate)"
        logger.info(f"  Event Type: TRAFFICSNAPSHOT. Aggregate event. Full details not exported here.")
    else:
        logger.info(f"  Event Type {event_data_for_export['SDKEventType']} not listed for detailed ANPR export.")

    logger.info(f"----------------------------------\n")

# --- Main Application Logic (same as before) ---
def main():
    # ... (identical to previous version)
    global g_sdk, g_login_id, g_analyzer_handle, DB_CONNECTION
    ensure_dir(IMAGE_DIR); initialize_csv(); initialize_database()
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
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        if DB_CONNECTION: DB_CONNECTION.close(); logger.info("DB closed on login fail.")
        return
    logger.info(f"Login OK. ID: {g_login_id}")
    logger.info(f"Subscribing to ALL IVS (Type: {ANPR_EVENT_TYPE}, Chan: {CHANNEL_ID})...")
    g_analyzer_handle = g_sdk.RealLoadPictureEx(g_login_id, CHANNEL_ID, ANPR_EVENT_TYPE, 1, AnalyzerDataCallback, 0, None)
    if g_analyzer_handle == 0:
        logger.error(f"Subscription failed (RealLoadPictureEx returned 0).")
        if hasattr(g_sdk, 'Logout'): g_sdk.Logout(g_login_id)
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        if DB_CONNECTION: DB_CONNECTION.close(); logger.info("DB closed on sub fail.")
        return
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
        if DB_CONNECTION: DB_CONNECTION.close(); logger.info("SQLite DB connection closed.")
        logging.shutdown()

if __name__ == "__main__":
    main()
