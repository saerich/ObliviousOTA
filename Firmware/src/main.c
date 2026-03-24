#include <ssot.h>
#include <esp_log.h>
#include <esp_err.h>
#include <NetUtils.h>
#include <NetworkedOPAQUE.h>
#include <BlindFetch.h>
#include <esp_timer.h>

#ifndef WIFI_SSID
#error "WIFI_SSID must be specified in .env"
#endif

#ifndef WIFI_PASSWORD
#error "WIFI_PASSWORD must be specified in .env"
#endif

#ifndef OPAQUE_PASSWORD
#error "OPAQUE_PASSWORD must be specified in .env"
#endif

#ifndef OPAQUE_SERVER_URL
#error "OPAQUE_SERVER_URL must be specified in .env"
#endif

const char* wifiSSID = WIFI_SSID;
const char* wifiPassword = WIFI_PASSWORD;
const char* opaquePassword = OPAQUE_PASSWORD;
const char* opaqueServerURL = OPAQUE_SERVER_URL;
const char* deviceFirmwareKey = FIRMWARE_KEY; // Under normal circumstances, this would be an EFUSE burned value from a fabricator. 
const char* TAG = "[Main]";


/**
 * @brief Primary entry point for the ESPIDF application, the intent of this application is to provide a one-shot example of
 * an implementation of a fully oblivious over the air updating mechanism, running on clock speed 160MHz
 * @author Darren Nevin
 */
void app_main()
{
    int64_t startTime = esp_timer_get_time();
    WiFiConnect(wifiSSID, wifiPassword);

    char macAddr[18];
    int64_t macAddrTime = esp_timer_get_time();
    GetDeviceMACAsString(macAddr);
    int64_t macAddrEndTime = esp_timer_get_time();
    int64_t opaqueInitTime = esp_timer_get_time();
    OPAQUEInit(macAddr);
    int64_t opaqueInitEndTime = esp_timer_get_time();

    WiFiSync(10000);
    
    int64_t opaqueRegisterStartTime = esp_timer_get_time();
    esp_err_t err = NetworkedOPAQUERegister(opaqueServerURL, macAddr, opaquePassword);
    int64_t opaqueRegisterEndTime = esp_timer_get_time();
    if(err == ESP_ERR_NOT_SUPPORTED) { ESP_LOGI("[Main]", "User is already registered."); }

    uint8_t skClient[OPAQUE_SHARED_SECRETBYTES];
    uint8_t exportKey[crypto_hash_sha512_BYTES];
    
    int64_t opaqueLoginTime = esp_timer_get_time();
    
    ESP_ERROR_CHECK(NetworkedOPAQUELogin(opaqueServerURL, macAddr, opaquePassword, skClient, exportKey));
    int64_t opaqueLoginEndTime = esp_timer_get_time();

    int64_t downloadStartTime = esp_timer_get_time();
    BlindDownloadFirmware(opaqueServerURL, deviceFirmwareKey, macAddr, skClient);
    int64_t downloadEndTime = esp_timer_get_time();

    ESP_LOGI("TIMING", "Device Started: %lld, Device stopped: %lld", startTime, downloadEndTime);
}
