#include "NetUtils.h"
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <string.h>

// static const char* TAG = "Network";
static volatile bool IsWiFiConnected = false; 

/// @brief Initializes the NVS Flash, required for networking functions, erasing and recreating it if NVS_NEW_VERSION or NVS_NO_FREE_PAGES.
/// @exception If nvs_flash_erase() fails, this will ESP_ERROR_CHECK abort the execution tree.
/// @return ESP_OK if everything worked, Error from nvs_flash_init() otherwise.
esp_err_t NetworkNVSInit()
{
    esp_err_t err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

/// @brief Gets the MAC address from the EFUSE of the ESP32.
/// @param macAddress uint8_t*[6] to hold the MAC address, or uint8_t*[8] if CONFIG_SOC_IEEE802154_SUPPORTED = y
/// @exception If the macAddress parameter is not specified, execution will abort with ESP_ERR_INVALID_ARG
/// @return Error from esp_efuse_mac_mac_get_default().
esp_err_t GetDeviceMAC(uint8_t* macAddress)
{
    if(!macAddress) { ESP_ERROR_CHECK(ESP_ERR_INVALID_ARG); }
    return esp_efuse_mac_get_default(macAddress);
}

/// @brief Gets the MAC address from the EFUSE of the ESP32, as a XX:XX:XX:XX:XX:XX formatted string
/// @param macAddress char*[18] to hold the MAC address
/// @exception If the macAddress parameter is not specified, execution will abort with ESP_ERR_INVALID_ARG
/// @return Error from esp_efuse_mac_mac_get_default().
esp_err_t GetDeviceMACAsString(char* macAddress)
{
    uint8_t macAddr[6];
    esp_err_t err = esp_efuse_mac_get_default(macAddr);
    if(err == ESP_OK) { sprintf(macAddress, "%02X:%02X:%02X:%02X:%02X:%02x", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]); }
    return err;
}

static void wifiHandle(void* arg, esp_event_base_t eventBase, int32_t eventId, void* eventData)
{
    if(eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_START) { esp_wifi_connect(); }
    else if(eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_DISCONNECTED)
    {
        IsWiFiConnected = false;
        esp_wifi_connect();
    }
    else if(eventBase == IP_EVENT && eventId == IP_EVENT_STA_GOT_IP)
    {
        esp_netif_t* netif = esp_netif_get_default_netif();
        esp_netif_dns_info_t dnsMain;
        ESP_ERROR_CHECK(esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dnsMain));
        if(dnsMain.ip.u_addr.ip4.addr == 0)
        {
            IsWiFiConnected = false;
            return;
        }
        IsWiFiConnected = true;
    }
}

/// @brief Connect to a WiFi Network.
/// @param ssid SSID of the network.
/// @param pwd Password to connect to the network.
/// @exception If NetworkNVSInit() fails, will abort via ESP_ERROR_CHECK
/// @exception If cannot init network interface, will abort via ESP_ERROR_CHECK
/// @exception If cannot create default event loop, will abort via ESP_ERROR_CHECK
/// @exception If cannot init wifi, will abort via ESP_ERROR_CHECK,
/// @exception If cannot register event handlers for WIIF_EVENT or IP_EVENT, will abort via ESP_ERROR_CHECK
/// @exception If cannot set STA mode on Wifi, will abort via ESP_ERROR_CHECK
/// @exception If cannot set the default config, will abort via ESP_ERROR_CHECK
/// @exception If cannot start wifi, will abort via ESP_ERROR_CHECK
/// @return ESP_OK -- Wait with WifiSync() to ensure connection.
esp_err_t WiFiConnect(const char* ssid, const char* pwd)
{
    IsWiFiConnected = false;
    ESP_ERROR_CHECK(NetworkNVSInit());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifiHandle, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, &wifiHandle, NULL));

    wifi_config_t wifiConfig =
    {
        .sta = 
        {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH
        }
    };

    strncpy((char*)wifiConfig.sta.ssid, ssid, sizeof(wifiConfig.sta.ssid));
    strncpy((char*)wifiConfig.sta.password, pwd, sizeof(wifiConfig.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifiConfig));
    ESP_ERROR_CHECK(esp_wifi_start());
    return ESP_OK;
}

/// @brief Waits for a WiFi Connection
/// @param timeoutMS Length of time in miliseconds to wait for connection.
/// @return Boolean of whether or not the connection was successful.
bool WiFiSync(int timeoutMS)
{
    int waited = 0;
    const int step = 200;
    
    while(!IsWiFiConnected && waited < timeoutMS)
    {
        vTaskDelay(pdMS_TO_TICKS(step));
        waited += step;
    }
    return IsWiFiConnected;
} 

bool WifiConnected() { return IsWiFiConnected; }