# --- START OF FILE app.py ---

from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import atexit
import os # Import os module
# Disable urllib3 warnings that might arise from verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__)

# --- Load API Keys from JSON ---
API_KEYS_DATA = {} # Stores {key: max_requests}

def load_api_keys(filename="api_keys.json"):
    """Loads API keys and their limits from a JSON file."""
    global API_KEYS_DATA
    try:
        if not os.path.exists(filename):
            app.logger.error(f"🛑 API keys file '{filename}' not found.")
            API_KEYS_DATA = {} # Ensure it's empty if file missing
            return

        with open(filename, "r") as f:
            keys_list = json.load(f)
            # Convert list to dictionary for faster lookup: {key: max_requests}
            API_KEYS_DATA = {item['key']: item['max_requests'] for item in keys_list}
            app.logger.info(f"✅ Successfully loaded {len(API_KEYS_DATA)} API keys from '{filename}'.")
            if not API_KEYS_DATA:
                 app.logger.warning(f"⚠️ API keys file '{filename}' is empty or contains no valid keys.")
    except json.JSONDecodeError:
        app.logger.error(f"🛑 Error decoding JSON from API keys file '{filename}'. Please check its format.")
        API_KEYS_DATA = {}
    except KeyError as e:
        app.logger.error(f"🛑 Missing key '{e}' in an item in API keys file '{filename}'. Each item must have 'key' and 'max_requests'.")
        API_KEYS_DATA = {}
    except Exception as e:
        app.logger.error(f"🛑 An unexpected error occurred while loading API keys from '{filename}': {e}")
        API_KEYS_DATA = {}

# Call load_api_keys at startup
load_api_keys()

# Dictionary to store remaining requests for each key used today
request_counters = {} # Stores {key: remaining_requests}

# 🔁 Reset request counters every day at 1 AM
def reset_request_counters():
    global request_counters
    request_counters = {}
    app.logger.info(f"✅ Request counters reset at {datetime.now()}")

scheduler = BackgroundScheduler(timezone="UTC") # Example: Set timezone if needed
scheduler.add_job(func=reset_request_counters, trigger='cron', hour=1, minute=0)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# 🔐 Load tokens (Added logging for empty/invalid files)
def load_tokens(server_name):
    # Ensure server_name is uppercase for consistent file matching
    server_name_upper = server_name.upper()
    try:
        if server_name_upper == "IND":
            token_file = "token_ind.json"
        elif server_name_upper in {"BR", "US", "SAC", "NA"}:
            token_file = "token_br.json"
        else:
            token_file = "token_bd.json" # Defaulting others to BD

        if not os.path.exists(token_file):
             app.logger.error(f"Token file '{token_file}' not found for server {server_name_upper}.")
             return None # Indicate failure clearly

        with open(token_file, "r") as f:
            tokens = json.load(f)
            # Check if tokens is a list and not empty
            if not isinstance(tokens, list):
                app.logger.error(f"Token file '{token_file}' for server {server_name_upper} does not contain a valid JSON list.")
                return None
            if not tokens:
                 app.logger.warning(f"Token file '{token_file}' for server {server_name_upper} is empty.")
                 return [] # Return empty list, consistent with no tokens found
            # Optional: Validate token structure within the list if needed
            # e.g., all(isinstance(t, dict) and "token" in t for t in tokens)
        app.logger.debug(f"Loaded {len(tokens)} tokens for server {server_name_upper} from {token_file}")
        return tokens
    except json.JSONDecodeError:
        app.logger.error(f"Error decoding JSON from token file '{token_file}' for server {server_name_upper}.")
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name_upper} from {token_file}: {e}")
        return None


# --- API Key and Rate Limit Validation (Accepts key as argument) ---
def validate_api_key(api_key):
    """
    Validates the provided API key against the loaded keys and checks rate limits.
    Accepts the API key as an argument.
    Returns an error response (tuple) if invalid or rate limited, otherwise None.
    """
    if not api_key:
        # This case might be less likely now with path parameters, but good to keep
        return jsonify({"error": "API key is missing in the URL path."}), 401

    if not API_KEYS_DATA:
         app.logger.error("API Keys data is empty or not loaded. Denying request.")
         # This is a server-side issue
         return jsonify({"error": "Server configuration error: API Keys not available."}), 500

    if api_key not in API_KEYS_DATA:
        app.logger.warning(f"Unauthorized access attempt with invalid API key: {api_key}")
        return jsonify({"error": "Unauthorized access. Invalid API key."}), 403

    # Get the specific max requests for this valid key
    max_requests_for_key = API_KEYS_DATA[api_key]

    # Initialize counter for this key if it's the first use today
    if api_key not in request_counters:
        request_counters[api_key] = max_requests_for_key
        app.logger.info(f"Initialized counter for key ending '...{api_key[-4:]}' with limit {max_requests_for_key}.")

    # Check if the limit is exceeded
    current_remaining = request_counters.get(api_key, 0) # Get current count safely
    if current_remaining <= 0:
        app.logger.warning(f"Request limit exceeded for API key ending '...{api_key[-4:]}'")
        return jsonify({
            "error": "Request limit exceeded for this key",
            "MaxRequest": max_requests_for_key,
            "RemainRequest": 0
        }), 429 # HTTP 429 Too Many Requests

    # Decrement the counter for this key
    request_counters[api_key] -= 1
    # Use debug level for frequent logs
    # app.logger.debug(f"Request valid for key ending '...{api_key[-4:]}'. Remaining: {request_counters[api_key]}/{max_requests_for_key}")

    # Return None on success, indicating validation passed
    return None
# --- END MODIFIED ---

# --- Encryption/Protobuf/Request Functions (Mostly Unchanged, added logging/error handling) ---

def encrypt_message(plaintext):
    try:
        # Ensure key and iv are bytes
        key = b'Yg&tc%DEuh6%Zc^8' # 16 bytes for AES-128
        iv = b'6oyZDr22E3ychjM%'  # 16 bytes for CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Ensure plaintext is bytes before padding
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}", exc_info=True)
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id) # Ensure UID is integer
        message.region = region.upper() # Ensure region is uppercase
        return message.SerializeToString()
    except ValueError:
        app.logger.error(f"Invalid UID format for like protobuf creation: {user_id}")
        return None
    except Exception as e:
        app.logger.error(f"Error creating like protobuf message: {e}", exc_info=True)
        return None

async def send_request(encrypted_uid_hex, token, url):
    """Sends a single asynchronous request."""
    try:
        # Convert hex string to bytes
        edata = bytes.fromhex(encrypted_uid_hex)

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            #'Expect': "100-continue", # Often not needed, can remove if causes issues
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        # Use a single session potentially for connection pooling if performance is critical
        # async with aiohttp.ClientSession(headers=headers) as session:
        # For simplicity here, creating session per request
        async with aiohttp.ClientSession() as session:
            # Disable SSL verification for aiohttp (like requests verify=False)
            # Use ssl=False carefully, only if you trust the endpoint or for debugging
            async with session.post(url, data=edata, headers=headers, ssl=False, timeout=10) as response: # Added timeout
                # Check status code
                if response.status != 200:
                    response_text = await response.text() # Read response body for logging
                    app.logger.error(f"Like request failed with status {response.status} for token ending ...{token[-5:]}. URL: {url}. Response: {response_text[:200]}")
                    return response.status # Return status for aggregation

                # Optionally log success or process response.text() if needed
                # response_data = await response.text()
                # app.logger.debug(f"Like request success (Status {response.status}) for token ending ...{token[-5:]}")
                return 200 # Indicate success explicitly

    except binascii.Error as e:
         app.logger.error(f"Hex decoding error in send_request: {e}. Encrypted UID Hex: {encrypted_uid_hex[:20]}...")
         return None # Indicate error
    except aiohttp.ClientError as e:
        # Covers connection errors, timeouts, etc.
        app.logger.error(f"AIOHTTP client error in send_request for token ending ...{token[-5:]}: {e}")
        return None # Indicate error
    except asyncio.TimeoutError:
         app.logger.error(f"AIOHTTP timeout during send_request for token ending ...{token[-5:]} to {url}")
         return None
    except Exception as e:
        app.logger.error(f"Generic exception in send_request for token ending ...{token[-5:]}: {e}", exc_info=True)
        return None # Indicate error


async def send_multiple_requests(uid, server_name, url):
    """Creates and sends multiple like requests concurrently."""
    # Ensure server_name is uppercase for consistency
    server_name_upper = server_name.upper()
    try:
        region = server_name_upper # Use uppercase server_name as region
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
             app.logger.error("Failed to create protobuf message for likes.")
             return 0 # Return 0 successes

        encrypted_uid_hex = encrypt_message(protobuf_message)
        if encrypted_uid_hex is None:
             app.logger.error("Failed to encrypt like message.")
             return 0 # Return 0 successes

        tokens = load_tokens(server_name_upper) # Use uppercase name
        if not tokens: # Handles None or empty list
            app.logger.error(f"No tokens loaded or found for server {server_name_upper} to send likes.")
            return 0 # Return 0 successes

        # Filter out invalid token entries just in case
        valid_tokens = [t["token"] for t in tokens if isinstance(t, dict) and "token" in t and t["token"]]
        if not valid_tokens:
             app.logger.warning(f"No valid 'token' strings found in the loaded token list for server {server_name_upper}.")
             return 0

        app.logger.info(f"Sending {len(valid_tokens)} like requests for UID {uid} on server {server_name_upper} to {url}...")
        tasks = [send_request(encrypted_uid_hex, token, url) for token in valid_tokens]

        # return_exceptions=True allows gather to complete even if some tasks fail
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results to count successes
        success_count = 0
        fail_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                fail_count += 1
                app.logger.error(f"Like task {i} failed with exception: {result}")
            elif result == 200:
                 success_count +=1
            elif isinstance(result, int): # HTTP error status code returned
                 fail_count += 1
                 # Logged already in send_request
            elif result is None: # None returned on other errors in send_request
                 fail_count += 1
                 # Logged already in send_request
            else: # Unexpected result type
                 fail_count += 1
                 app.logger.error(f"Like task {i} returned unexpected result: {result}")


        app.logger.info(f"Like request batch completed for UID {uid}: {success_count} succeeded, {fail_count} failed out of {len(valid_tokens)} attempts.")
        return success_count # Return the number of successful requests

    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests for UID {uid}: {e}", exc_info=True)
        return 0 # Return 0 successes on outer exception

# --- Functions for GetPlayerPersonalShow ---

def create_protobuf(uid):
    """Creates protobuf message for GetPlayerPersonalShow."""
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid) # Ensure UID is integer
        message.garena = 1
        return message.SerializeToString()
    except ValueError:
         app.logger.error(f"Invalid UID format for GetPlayerPersonalShow protobuf creation: {uid}")
         return None
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf for UID {uid}: {e}", exc_info=True)
        return None

def enc(uid):
    """Encrypts the GetPlayerPersonalShow protobuf message."""
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None # Error already logged
    encrypted_uid_hex = encrypt_message(protobuf_data)
    if encrypted_uid_hex is None:
         app.logger.error(f"Encryption failed for GetPlayerPersonalShow message for UID {uid}")
         return None
    return encrypted_uid_hex

def make_request(encrypted_uid_hex, server_name, token):
    """Makes a synchronous request to GetPlayerPersonalShow."""
    # Ensure server_name is uppercase for consistent URL selection
    server_name_upper = server_name.upper()
    try:
        if not encrypted_uid_hex or not isinstance(encrypted_uid_hex, str):
             app.logger.error("Invalid encrypted data provided to make_request.")
             return None
        if not token:
             app.logger.error("No token provided to make_request.")
             return None

        # Determine URL based on uppercase server_name
        if server_name_upper == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name_upper in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else: # Assuming BD or others fall here
            url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

        # Convert hex string to bytes
        try:
            edata = bytes.fromhex(encrypted_uid_hex)
        except ValueError:
             app.logger.error(f"Invalid hex string for data in make_request: {encrypted_uid_hex[:20]}...")
             return None

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            #'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }

        # Disable SSL verification for requests, use with caution. Added timeout.
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10) # 10-second timeout

        # Raise HTTPError for bad responses (4xx client error or 5xx server error)
        response.raise_for_status()

        binary_content = response.content
        if not binary_content:
             app.logger.warning(f"Empty response content received from {url} for token ending ...{token[-5:]}")
             return None

        # Decode the protobuf content
        decoded_info = decode_protobuf(binary_content)
        return decoded_info # Returns the decoded protobuf object or None

    except requests.exceptions.HTTPError as e:
        # Log specific HTTP errors (like 401 Unauthorized, 404 Not Found, 5xx Server Error)
        app.logger.error(f"HTTP error in make_request to {url}: {e.response.status_code} {e.response.reason}. Token ending ...{token[-5:]}. Response: {e.response.text[:200]}")
        return None
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection error in make_request to {url}: {e}")
        return None
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout error in make_request to {url}")
        return None
    except requests.exceptions.RequestException as e:
        # Catch other request-related errors
        app.logger.error(f"Network error in make_request to {url}: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error in make_request: {e}", exc_info=True)
        return None

def decode_protobuf(binary_data):
    """Decodes the binary protobuf data for GetPlayerPersonalShow."""
    try:
        if not binary_data:
            app.logger.error("Attempted to decode empty binary data.")
            return None
        items = like_count_pb2.Info()
        items.ParseFromString(binary_data)
        return items
    except DecodeError as e:
        # Log part of the binary data (carefully, might contain sensitive info if not protobuf)
        binary_preview = binascii.hexlify(binary_data[:50]).decode('utf-8', 'ignore')
        app.logger.error(f"Error decoding Protobuf data: {e}. Binary data start (hex): {binary_preview}...")
        return None
    except Exception as e:
         app.logger.error(f"Unexpected error during protobuf decoding: {e}", exc_info=True)
         return None


# --- MODIFIED: Route Definition and Function Signature ---
# Changed route from '/like/<uid>/<server_name>/<key>' to '/<uid>/<server_name>/<key>'
@app.route('/<uid>/<server_name>/<key>', methods=['GET'])
def handle_requests(uid, server_name, key):
    """Handles like requests using path parameters: /UID/SERVER_NAME/API_KEY."""

    # --- API Key validation uses the 'key' argument ---
    validation_result = validate_api_key(key) # Pass the key from the path
    if validation_result: # If validation failed, it returns the error response
        return validation_result
    # --- END MODIFIED ---

    # --- Input Validation ---
    # Parameters uid, server_name, key are now directly available from function args
    # Convert server_name to uppercase for consistent handling
    server_name_upper = server_name.upper()

    # Basic UID format check (should be digits)
    if not uid.isdigit():
         app.logger.warning(f"Invalid UID format received: {uid}")
         return jsonify({"error": "Invalid UID format. UID must be numeric."}), 400

    # --- Get Key-Specific Limits for Response ---
    # Retrieve limits safely using .get() with defaults, using 'key' argument
    # We know the key exists because validation passed
    current_max_requests = API_KEYS_DATA.get(key, 0)
    # Remaining requests might change during processing, get the value *after* decrementing
    remaining_requests = request_counters.get(key, 0)

    try:
        # This synchronous function wraps the core logic, including the asyncio part.
        # Note: Running asyncio.run inside a sync Flask route blocks the worker thread.
        def process_request():
            # Load tokens needed for checking profile and sending likes
            # Pass the uppercase server name
            tokens = load_tokens(server_name_upper)
            if tokens is None: # Check specifically for None indicating loading error
                app.logger.error(f"Token loading failed for server {server_name_upper} in process_request.")
                raise Exception(f"Could not load necessary tokens for server '{server_name_upper}'. Check server name and token files.")
            if not tokens: # Check for empty list
                app.logger.error(f"No tokens found for server {server_name_upper} in process_request.")
                raise Exception(f"No tokens available for server '{server_name_upper}'. Cannot proceed.")

            # Use the first valid token for checking likes before/after
            # Ensure the token list is not empty and the first item is valid
            check_token = None
            if isinstance(tokens, list) and len(tokens) > 0 and isinstance(tokens[0], dict) and "token" in tokens[0]:
                check_token = tokens[0]['token']

            if not check_token:
                 app.logger.error(f"Invalid token structure or empty/invalid first token for server {server_name_upper}.")
                 raise Exception(f"Invalid or missing token data for server '{server_name_upper}' needed for player check.")

            # Encrypt UID for checking likes (GetPlayerPersonalShow)
            encrypted_uid_check = enc(uid)
            if encrypted_uid_check is None:
                # Error already logged in enc() or create_protobuf()
                raise Exception("Encryption of UID failed for player info check.")

            # --- Get likes BEFORE sending like requests ---
            app.logger.info(f"Checking initial likes for UID {uid} on {server_name_upper}...")
            # Pass uppercase server name to make_request
            before_info = make_request(encrypted_uid_check, server_name_upper, check_token)
            if before_info is None:
                # Error logged in make_request. Give a user-friendly message.
                raise Exception(f"Failed to retrieve initial player info for UID {uid} on server '{server_name_upper}'. Check UID/server or if the check token is valid.")

            # Safely parse protobuf response and extract initial info
            try:
                # Access protobuf fields directly
                before_account_info = getattr(before_info, 'AccountInfo', None)
                if before_account_info is None:
                    raise ValueError("AccountInfo field missing in initial response")

                before_like = getattr(before_account_info, 'Likes', 0)
                player_name_before = getattr(before_account_info, 'PlayerNickname', 'N/A')
                player_uid_before = getattr(before_account_info, 'UID', 0)

                # Validate if the returned UID matches the requested one
                if player_uid_before == 0 or str(player_uid_before) != uid:
                     app.logger.warning(f"UID mismatch or invalid UID in initial response. Requested: {uid}, Got: {player_uid_before}. Name: '{player_name_before}'")
                     # If the UID doesn't match, the player likely doesn't exist on that server or the UID is wrong.
                     raise Exception(f"Could not find player with UID {uid} on server '{server_name_upper}' or UID mismatch in response.")

                app.logger.info(f"Initial check OK for UID {uid}: Likes={before_like}, Name='{player_name_before}'")

            except (AttributeError, ValueError) as e:
                 app.logger.error(f"Error accessing fields in initial player info Protobuf for UID {uid}: {e}")
                 raise Exception("Error parsing initial player info response.")


            # --- Send the like requests asynchronously ---
            # Determine the correct URL for sending likes based on uppercase server name
            if server_name_upper == "IND":
                like_url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name_upper in {"BR", "US", "SAC", "NA"}:
                like_url = "https://client.us.freefiremobile.com/LikeProfile"
            else: # Assuming BD or others
                like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

            app.logger.info(f"Attempting to send likes for UID {uid} to {like_url}...")
            # Pass uppercase server name to async function
            num_success_likes = asyncio.run(send_multiple_requests(uid, server_name_upper, like_url))
            app.logger.info(f"Like sending process completed for UID {uid}. Successful requests: {num_success_likes}")


            # --- Get likes AFTER sending like requests ---
            # Use the same encrypted UID and token as the 'before' check
            app.logger.info(f"Checking final likes for UID {uid} on {server_name_upper}...")
            # Pass uppercase server name
            after_info = make_request(encrypted_uid_check, server_name_upper, check_token)
            if after_info is None:
                app.logger.error(f"Failed to retrieve player info after like requests for UID {uid} on {server_name_upper}.")
                raise Exception("Failed to retrieve player info after sending likes. Cannot confirm final like count.")


            # Safely parse protobuf response and extract final info
            try:
                after_account_info = getattr(after_info, 'AccountInfo', None)
                if after_account_info is None:
                    raise ValueError("AccountInfo field missing in final response")

                after_like = getattr(after_account_info, 'Likes', 0)
                player_name_after = getattr(after_account_info, 'PlayerNickname', player_name_before)
                player_uid_after = getattr(after_account_info, 'UID', player_uid_before)

                if str(player_uid_after) != uid:
                     app.logger.warning(f"UID mismatch in final response. Requested: {uid}, Got: {player_uid_after}. Name: '{player_name_after}'")

                app.logger.info(f"Final check OK for UID {uid}: Likes={after_like}, Name='{player_name_after}'")

            except (AttributeError, ValueError) as e:
                 app.logger.error(f"Error accessing fields in final player info Protobuf for UID {uid}: {e}")
                 raise Exception("Error parsing final player info response.")


            # Calculate likes given and determine status
            like_given = after_like - before_like
            like_given = max(0, like_given) # Ensure non-negative
            status = 1 if like_given > 0 else 2

            if like_given == 0:
                 if num_success_likes > 0:
                      app.logger.warning(f"Sent {num_success_likes} successful like requests for UID {uid}, but no change in like count detected (Before: {before_like}, After: {after_like}). Possible server delay or issue.")
                 else:
                      app.logger.info(f"No successful like requests were sent for UID {uid}, and no like count change detected (Before: {before_like}, After: {after_like}).")
            else:
                 app.logger.info(f"Detected {like_given} new likes for UID {uid} (Before: {before_like}, After: {after_like}). Successful like requests: {num_success_likes}.")

            # --- Return the final result ---
            return {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name_after,
                "UID": int(player_uid_after), # Use UID from response
                "status": status,
                "SuccessfulLikeRequests": num_success_likes,
                "MaxRequest": current_max_requests,
                "RemainRequest": remaining_requests
            }

        # Execute the synchronous wrapper function
        result_data = process_request()
        return jsonify(result_data), 200 # HTTP 200 OK

    except Exception as e:
        # Log the exception with traceback for debugging
        # Use the original server_name (or upper) and uid from args in the error response
        app.logger.error(f"Error processing request for UID {uid}, Server {server_name_upper}: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "UID": uid,
            "ServerName": server_name_upper, # Use consistent uppercase name
            "MaxRequest": current_max_requests,
            "RemainRequest": remaining_requests
            }), 500 # HTTP 500 Internal Server Error


if __name__ == '__main__':
    # Railway theke port nibe, na pele default 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# --- END OF FILE app.py ---
