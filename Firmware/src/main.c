#include <ssot.h>
#include <esp_log.h>
#include <esp_err.h>
#include <NetUtils.h>
#include <NetworkedOPAQUE.h>
#ifndef WIFI_SSID
#error "WIFI_SSID must be specified in .env"
#endif

#ifndef WIFI_PASSWORD
#error "WIFI_PASSWORD must be specified in .env"
#endif

#ifndef OPAQUE_PASSWORD
#error "OPAQUE_PASSWORD must be specified in .env"
#endif

const char* wifiSSID = WIFI_SSID;
const char* wifiPassword = WIFI_PASSWORD;
const char* opaquePassword = OPAQUE_PASSWORD;
const char* TAG = "[Main]";
/**
 * @brief Primary entry point for the ESPIDF application, the intent of this application is to provide a one-shot example of
 * an implementation of a fully oblivious over the air updating mechanism, running on clock speed 160MHz
 * @author Darren Nevin
 */
void app_main()
{
    WiFiConnect(wifiSSID, wifiPassword);

    char macAddr[18];
    GetDeviceMACAsString(macAddr);
    OPAQUEInit(macAddr);

    WiFiSync(10000);
    NetworkedOPAQUERegister(opaquePassword);
    
}