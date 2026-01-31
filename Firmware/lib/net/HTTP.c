#include "HTTP.h"
#include <esp_http_client.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_crt_bundle.h>

static const char* TAG = "HTTP";
static const int HTTP_BUFFER_MAX = 4096;

static esp_err_t onHttpReceive(esp_http_client_event_t* evt)
{
    HTTPBufferContext_t* ctx = (HTTPBufferContext_t*)evt->user_data;

    switch(evt->event_id)
    {
        case HTTP_EVENT_ON_DATA:
            int copyLen = evt->data_len;
            if(ctx->bufLen + copyLen >= ctx->bufSize) { copyLen = ctx->bufSize - ctx->bufLen -1; }

            if(copyLen > 0)
            {
                memcpy(ctx->buf + ctx->bufLen, evt->data, copyLen);
                ctx->bufLen += copyLen;
                ctx->buf[ctx->bufLen] = '\0';
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

cJSON* HTTPGetJSON(const char* url, int* statusCode)
{
    cJSON* root = NULL;
    char* buf = NULL;

    buf = malloc(HTTP_BUFFER_MAX);
    if(!buf) 
    {
        ESP_LOGE(TAG, "Could not allocate response buffer for HTTP request.");
        return NULL;
    }
    
    HTTPBufferContext_t ctx =
    {
        .buf = buf,
        .bufLen = 0,
        .bufSize = HTTP_BUFFER_MAX
    };

    esp_http_client_config_t config =
    {
        .url = url,
        .method = HTTP_METHOD_GET,
        .event_handler = onHttpReceive,
        .user_data = &ctx,
        .crt_bundle_attach = esp_crt_bundle_attach
    };

    esp_http_client_handle_t cli = esp_http_client_init(&config);
    if(!cli)
    {
        ESP_LOGE(TAG, "Failed to create HTTP Client.");
        free(buf);
        return NULL;
    }

    esp_err_t err = esp_http_client_perform(cli);
    if(err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(cli);
        free(buf);
        return NULL;
    }

    int stat = esp_http_client_get_status_code(cli);
    if(statusCode) { *statusCode = stat; }

    if(stat < 200 || stat >= 300)
    {
        ESP_LOGE(TAG, "Non-Successful status code from HTTP Request.");
        esp_http_client_cleanup(cli);
        free(buf);
        return NULL;
    }

    if(ctx.bufLen < ctx.bufSize) { ctx.buf[ctx.bufLen] = '\0'; }
    else { ctx.buf[ctx.bufSize-1] = '\0'; }
    ESP_LOGD(TAG, "Raw JSON: %s", ctx.buf);

    root = cJSON_Parse(ctx.buf);
    if(!root)
    {
        const char* errPtr = cJSON_GetErrorPtr();
        if(errPtr != NULL) { ESP_LOGE(TAG, "JSON parse error before %s", errPtr); }
        else { ESP_LOGE(TAG, "Unknown JSON parse error."); }
    }

    esp_http_client_cleanup(cli);
    free(buf);
    return root; 
}

void HTTPGet(const char* url, int* statusCode)
{
    char* buf = NULL;

    buf = malloc(HTTP_BUFFER_MAX);
    if(!buf) 
    {
        ESP_LOGE(TAG, "Could not allocate response buffer for HTTP request.");
        return;
    }
    
    HTTPBufferContext_t ctx =
    {
        .buf = buf,
        .bufLen = 0,
        .bufSize = HTTP_BUFFER_MAX
    };

    esp_http_client_config_t config =
    {
        .url = url,
        .method = HTTP_METHOD_GET,
        .event_handler = onHttpReceive,
        .user_data = &ctx,
        .crt_bundle_attach = esp_crt_bundle_attach
    };

    esp_http_client_handle_t cli = esp_http_client_init(&config);
    if(!cli)
    {
        ESP_LOGE(TAG, "Failed to create HTTP Client.");
        free(buf);
        return;
    }

    esp_err_t err = esp_http_client_perform(cli);
    if(err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(cli);
        free(buf);
        return;
    }

    int stat = esp_http_client_get_status_code(cli);
    if(statusCode) { *statusCode = stat; }

    if(stat < 200 || stat >= 300)
    {
        ESP_LOGE(TAG, "Non-Successful status code from HTTP Request.");
        esp_http_client_cleanup(cli);
        free(buf);
        return;
    }

    esp_http_client_cleanup(cli);
    free(buf);
}

void URLEncodeByteArray(const uint8_t* data, size_t len, char* out, size_t outSize)
{
    static const char hex[] = "0123456789ABCDEF";

    if(outSize < (len * 2 + 1)) { return; }

    for(size_t i = 0; i < len; i++)
    {
        out[i*2] = hex[data[i] >> 4];
        out[i*2+1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}