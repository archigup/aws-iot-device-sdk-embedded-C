/*
 * AWS IoT Device SDK for Embedded C V202009.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* POSIX includes. */
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

/* Include Demo Config as the first non-system header. */
#include "demo_config.h"

/* Common HTTP demo utilities. */
#include "http_demo_utils.h"

/* HTTP API header. */
#include "core_http_client.h"

/* OpenSSL transport header. */
#include "openssl_posix.h"

/* Retry utilities. */
#include "retry_utils.h"

/* Check that TLS port of the server is defined. */
#ifndef HTTPS_PORT
    #error "Please define a HTTPS_PORT."
#endif

/* Check that a path for Root CA Certificate is defined. */
#ifndef ROOT_CA_CERT_PATH
    #error "Please define a ROOT_CA_CERT_PATH."
#endif

/* Check that a presigned url for the target S3 file is defined. */
#ifndef S3_PRESIGNED_URL
    #error "Please define a S3_PRESIGNED_URL."
#endif

/* Check that a path for HTTP Method GET is defined. */
#ifndef S3_FILE_SIZE
    #error "Please define a S3_FILE_SIZE."
#endif

/**
 * @brief ALPN protocol name to be sent as part of the ClientHello message.
 *
 * @note When using ALPN, port 443 must be used to connect to AWS IoT Core.
 */
#define IOT_CORE_ALPN_PROTOCOL_NAME    "\x0ex-amzn-http-ca"

/**
 * @brief Delay in seconds between each iteration of the demo.
 */
#define DEMO_LOOP_DELAY_SECONDS        ( 5U )

/* Check that transport timeout for transport send and receive is defined. */
#ifndef TRANSPORT_SEND_RECV_TIMEOUT_MS
    #define TRANSPORT_SEND_RECV_TIMEOUT_MS    ( 1000 )
#endif

/* Check that size of the user buffer is defined. */
#ifndef USER_BUFFER_LENGTH
    #define USER_BUFFER_LENGTH    ( 4096 )
#endif

/* Check that request queue name is defined. */
#ifndef REQUEST_QUEUE
    #define REQUEST_QUEUE    "/demo_request_queue"
#endif

/* Check that request queue name is defined. */
#ifndef RESPONSE_QUEUE
    #define RESPONSE_QUEUE    "/demo_response_queue"
#endif

/**
 * @brief Field name of the HTTP Range header to read from server response.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD           "Content-Range"

/**
 * @brief Length of the HTTP Range header field.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD_LENGTH    ( sizeof( HTTP_CONTENT_RANGE_HEADER_FIELD ) - 1 )

/* The location of the host address within string S3_PRESIGNED_URL. */
static const char * pAddress = NULL;

/* The host address string extracted from S3_PRESIGNED_URL. */
static char serverHost[ MAX_HOST_ADRESS_LENGTH ];

/* The length of the host address found in string S3_PRESIGNED_URL. */
static size_t serverHostLength = 0;

/**
 * @brief Data type for request queue.
 *
 * In addition to sending the headers struct, we need to send the buffer it uses.
 * The pointer to the buffer in the headers struct will be incorrect after
 * it is received so will need to be fixed.
 */
typedef struct RequestItem
{
    HTTPRequestHeaders_t requestHeaders;
    uint8_t headersBuffer[ USER_BUFFER_LENGTH ];
} RequestItem_t;

/**
 * @brief Data type for response queue.
 *
 * In addition to sending the response struct, we need to send the buffer it uses.
 * The pointer to the buffer in the response struct will be incorrect after
 * it is received so will need to be fixed.
 */
typedef struct ResponseItem
{
    HTTPResponse_t response;
    uint8_t responseBuffer[ USER_BUFFER_LENGTH ];
} ResponseItem_t;

/*-----------------------------------------------------------*/

/**
 * @brief Connect to HTTP server with reconnection retries.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
static int32_t connectToServer( NetworkContext_t * pNetworkContext );

/**
 * @brief Enqueue HTTP requests based on a specified method and path.
 *
 * @param[in] pHost The host name of the server.
 * @param[in] pMethod The HTTP request method.
 * @param[in] pPath The Request-URI to the objects of interest.
 * @param[in] requestQueue The queue to write requests to.
 * @param[out] requestCount The number of HTTP requests queued.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on success.
 */
static int requestS3ObjectFile( const char * pHost,
                                const char * pMethod,
                                const char * pPath,
                                mqd_t requestQueue,
                                size_t * requestCount );


/**
 * @brief Processes HTTP responses from response queue.
 *
 * @param[in] responseQueue The queue to read response from.
 * @param[in] requestCount The number of HTTP responses to read.
 */
static void retrieveS3ObjectFile( mqd_t responseQueue,
                                  size_t * requestCount );

/**
 * @brief Enqueue HTTP requests based on a specified method and path.
 *
 * @param[in] pTransportInterface The transport interface for making network calls.
 *
 * @return -1 on failure; PID of HTTP thread on success.
 */
static pid_t startHTTPThread( const TransportInterface_t * pTransportInterface );

/*-----------------------------------------------------------*/

static int32_t connectToServer( NetworkContext_t * pNetworkContext )
{
    int32_t returnStatus = EXIT_FAILURE;
    /* Status returned by OpenSSL transport implementation. */
    OpensslStatus_t opensslStatus;
    /* Credentials to establish the TLS connection. */
    OpensslCredentials_t opensslCredentials;
    /* Information about the server to send the HTTP requests. */
    ServerInfo_t serverInfo;

    /* Initialize TLS credentials. */
    ( void ) memset( &opensslCredentials, 0, sizeof( opensslCredentials ) );
    opensslCredentials.pRootCaPath = ROOT_CA_CERT_PATH;

    /* ALPN is required when communicating to AWS IoT Core over port 443 through HTTP. */
    if( HTTPS_PORT == 443 )
    {
        opensslCredentials.pAlpnProtos = IOT_CORE_ALPN_PROTOCOL_NAME;
        opensslCredentials.alpnProtosLen = strlen( IOT_CORE_ALPN_PROTOCOL_NAME );
    }

    /* serverHost should consist only of the host address located in S3_PRESIGNED_URL. */
    memcpy( serverHost, pAddress, serverHostLength );

    /* Initialize server information. */
    serverInfo.pHostName = serverHost;
    serverInfo.hostNameLength = serverHostLength;
    serverInfo.port = HTTPS_PORT;

    /* Establish a TLS session with the HTTP server. This example connects
     * to the HTTP server as specified in SERVER_HOST and HTTPS_PORT
     * in demo_config.h. */
    LogInfo( ( "Establishing a TLS session with %s:%d.",
               serverHost,
               HTTPS_PORT ) );

    opensslStatus = Openssl_Connect( pNetworkContext,
                                     &serverInfo,
                                     &opensslCredentials,
                                     TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                     TRANSPORT_SEND_RECV_TIMEOUT_MS );

    if( opensslStatus == OPENSSL_SUCCESS )
    {
        returnStatus = EXIT_SUCCESS;
    }
    else
    {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int requestS3ObjectFile( const char * pHost,
                                const char * pMethod,
                                const char * pPath,
                                mqd_t requestQueue,
                                size_t * requestCount )
{
    int returnStatus = EXIT_SUCCESS;
    HTTPStatus_t httpStatus = HTTP_SUCCESS;

    /* Return value of mq_send */
    int mqerror = 0;

    /* Configurations of the initial request headers */
    HTTPRequestInfo_t requestInfo = { 0 };
    /* Request data sent over queue */
    RequestItem_t requestItem = { 0 };

    /* The size of the file we are trying to download in S3. */
    size_t fileSize = S3_FILE_SIZE;

    /* The number of bytes we want to request within each range of the file. */
    size_t numReqBytes = 0;
    /* curByte indicates which starting byte we want to download next. */
    size_t curByte = 0;

    /* Initialize the request object. */
    requestInfo.pHost = pHost;
    requestInfo.hostLen = strlen( pHost );
    requestInfo.method = pMethod;
    requestInfo.methodLen = strlen( pMethod );
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );

    /* Set "Connection" HTTP header to "keep-alive" so that multiple requests
     * can be sent over the same established TCP connection. This is done in
     * order to download the file in parts. */
    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Set the buffer used for storing request headers. */
    requestItem.requestHeaders.pBuffer = requestItem.headersBuffer;
    requestItem.requestHeaders.bufferLen = sizeof( requestItem.headersBuffer );

    /* Ensure requested amount will fit in buffer */
    if( fileSize < sizeof( requestItem.headersBuffer ) - HTTP_MAX_RESPONSE_HEADERS_SIZE_BYTES )
    {
        numReqBytes = fileSize;
    }
    else
    {
        numReqBytes = sizeof( requestItem.headersBuffer ) - HTTP_MAX_RESPONSE_HEADERS_SIZE_BYTES;
    }

    /* Here we iterate sending byte range requests until the full file has been
     * downloaded. We keep track of the next byte to download with curByte.
     * When this reaches the fileSize we stop downloading. */
    while( curByte < fileSize && httpStatus == HTTP_SUCCESS && returnStatus == EXIT_SUCCESS )
    {
        if( httpStatus == HTTP_SUCCESS )
        {
            httpStatus = HTTPClient_InitializeRequestHeaders( &( requestItem.requestHeaders ),
                                                              &requestInfo );
        }

        if( httpStatus == HTTP_SUCCESS )
        {
            httpStatus = HTTPClient_AddRangeHeader( &( requestItem.requestHeaders ),
                                                    curByte,
                                                    curByte + numReqBytes - 1 );
        }
        else
        {
            LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
        }

        if( httpStatus == HTTP_SUCCESS )
        {
            /* Enqueue the request. */
            LogInfo( ( "Enqueuing %d bytes of S3 Object out of %d total bytes, from %s...:  ",
                       ( int32_t ) ( curByte + numReqBytes - 1 ),
                       ( int32_t ) fileSize,
                       pHost ) );
            LogInfo( ( "Request Headers:\n%.*s",
                       ( int32_t ) requestItem.requestHeaders.headersLen,
                       ( char * ) requestItem.requestHeaders.pBuffer ) );

            mqerror = mq_send( requestQueue,
                               ( char * ) &requestItem,
                               sizeof( RequestItem_t ),
                               0 );

            if( mqerror != 0 )
            {
                LogError( ( "Failed to write to request queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }
            else
            {
                *requestCount += 1;
            }
        }
        else
        {
            LogError( ( "Failed to add Range header to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
        }

        curByte += numReqBytes;

        if( ( fileSize - curByte ) < numReqBytes )
        {
            numReqBytes = fileSize - curByte;
        }
    }

    if( httpStatus != HTTP_SUCCESS )
    {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static void retrieveS3ObjectFile( mqd_t responseQueue,
                                  size_t * requestCount )
{
    /* Return value of mq_receive */
    int mqread = 0;

    /* Request data sent over queue */
    ResponseItem_t responseItem = { 0 };

    while( *requestCount > 0 )
    {
        /* Read response from queue */
        mqread = mq_receive( responseQueue, ( char * ) &responseItem,
                             sizeof( ResponseItem_t ), NULL );
        responseItem.response.pBuffer = responseItem.responseBuffer;

        if( mqread == -1 )
        {
            LogError( ( "Failed to read from response queue with error %s.",
                        strerror( errno ) ) );
        }
        else if( mqread != sizeof( ResponseItem_t ) )
        {
            LogError( ( "Response from response queue has incorrect size." ) );
        }
        else
        {
            LogInfo( ( "Main thread received HTTP response" ) );
            LogInfo( ( "Response Headers:\n%.*s",
                       ( int32_t ) responseItem.response.headersLen,
                       responseItem.response.pHeaders ) );
            LogInfo( ( "Response Status:\n%u", responseItem.response.statusCode ) );
            LogInfo( ( "Response Body:\n%.*s\n", ( int32_t ) responseItem.response.bodyLen,
                       responseItem.response.pBody ) );

            *requestCount -= 1;
        }
    }
}

/*-----------------------------------------------------------*/

static pid_t startHTTPThread( const TransportInterface_t * pTransportInterface )
{
    mqd_t requestQueue = -1;
    mqd_t responseQueue = -1;
    HTTPStatus_t httpStatus = HTTP_SUCCESS;

    /* Return value of mq_recieve */
    int mqread = 0;
    /* Return value of mq_send */
    int mqerror = 0;

    /* Queues for HTTP requests and responses */
    RequestItem_t requestItem = { 0 };
    ResponseItem_t responseItem = { 0 };

    /* Return value of fork */
    pid_t forkPID = -1;

    /* Fork to create the HTTP thread */
    forkPID = fork();

    if( forkPID == 0 )
    {
        /* HTTP thread */

        /* Open queues for read/write */
        requestQueue = mq_open( REQUEST_QUEUE, O_RDONLY );
        responseQueue = mq_open( RESPONSE_QUEUE, O_WRONLY );

        /* Initialize response struct */
        responseItem.response.pBuffer = responseItem.responseBuffer;
        responseItem.response.bufferLen = sizeof( responseItem.responseBuffer );

        for( ; ; )
        {
            /* Read request from queue */
            mqread = mq_receive( requestQueue,
                                 ( char * ) &requestItem,
                                 sizeof( RequestItem_t ),
                                 NULL );
            requestItem.requestHeaders.pBuffer = requestItem.headersBuffer;

            if( mqread == -1 )
            {
                LogError( ( "Failed to read from request queue with error %s.",
                            strerror( errno ) ) );
            }

            if( mqread != sizeof( RequestItem_t ) )
            {
                LogError( ( "Response from request queue has incorrect size." ) );
            }

            LogInfo( ( "HTTP thread retrieved request." ) );
            LogInfo( ( "Request Headers:\n%.*s",
                       ( int32_t ) requestItem.requestHeaders.headersLen,
                       ( char * ) requestItem.requestHeaders.pBuffer ) );

            httpStatus = HTTPClient_Send( pTransportInterface,
                                          &requestItem.requestHeaders,
                                          NULL,
                                          0,
                                          &responseItem.response,
                                          0 );

            if( httpStatus == HTTP_SUCCESS )
            {
                LogInfo( ( "HTTP thread received HTTP response" ) );
                /* Write response to queue */
                mqerror = mq_send( responseQueue,
                                   ( char * ) &responseItem,
                                   sizeof( ResponseItem_t ),
                                   0 );

                if( mqerror != 0 )
                {
                    LogError( ( "Failed to write to response queue with error %s.",
                                strerror( errno ) ) );
                }
            }
            else
            {
                LogError( ( "Failed to send HTTP request: Error=%s.",
                            HTTPClient_strerror( httpStatus ) ) );
            }
        }
    }
    else if( forkPID == -1 )
    {
        LogError( ( "Error forking." ) );
    }

    return forkPID;
}

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of demo.
 *
 * This example resolves a domain, establishes a TCP connection, validates the
 * server's certificate using the root CA certificate defined in the config header,
 * then finally performs a TLS handshake with the HTTP server so that all communication
 * is encrypted. After which, HTTP Client library API is used to download the
 * S3 file by sending multiple GET requests, filling up the response buffer
 * each time until all parts are downloaded. If any request fails, an error
 * code is returned.
 *
 * @note This example is single-threaded and uses statically allocated memory.
 *
 */
int main( int argc,
          char ** argv )
{
    /* Return value of main. */
    int32_t returnStatus = EXIT_SUCCESS;
    /* HTTPS Client library return status. */
    HTTPStatus_t httpStatus = HTTP_SUCCESS;

    /* The location of the path within string S3_PRESIGNED_URL. */
    const char * pPath = NULL;
    /* The length of the path within string S3_PRESIGNED_URL. */
    size_t pathLen = 0;

    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t transportInterface = { 0 };
    /* The network context for the transport layer interface. */
    NetworkContext_t networkContext = { 0 };

    /* Queue for http requests to be handled by http thread */
    mqd_t requestQueue = -1;
    /* Queue for http responses retrieved by http thread */
    mqd_t responseQueue = -1;
    /* Settings for constructing queues */
    struct mq_attr queueSettings;

    /* Number of requests made */
    size_t requestCount = 0;

    /* PID of HTTP thread. */
    pid_t httpThread = -1;

    ( void ) argc;
    ( void ) argv;

    for( ; ; )
    {
        LogInfo( ( "HTTPS Client Asynchronous S3 download demo using pre-signed URL:\n%s", S3_PRESIGNED_URL ) );

        /**************************** Parse Signed URL. ******************************/
        if( returnStatus == EXIT_SUCCESS )
        {
            /* Retrieve the path location from S3_PRESIGNED_URL. This function returns the length of the path
             * without the query into pathLen. */
            httpStatus = getUrlPath( S3_PRESIGNED_URL,
                                     strlen( S3_PRESIGNED_URL ),
                                     &pPath,
                                     &pathLen );

            if( httpStatus != HTTP_SUCCESS )
            {
                LogError( ( "An error occurred in getUrlPath() on URL %s. Error code: %d",
                            S3_PRESIGNED_URL,
                            httpStatus ) );
                returnStatus = EXIT_FAILURE;
            }
        }

        if( returnStatus == EXIT_SUCCESS )
        {
            /* Retrieve the address location and length from the S3_PRESIGNED_URL. */
            httpStatus = getUrlAddress( S3_PRESIGNED_URL,
                                        strlen( S3_PRESIGNED_URL ),
                                        &pAddress,
                                        &serverHostLength );

            if( httpStatus != HTTP_SUCCESS )
            {
                LogError( ( "An error occurred in getUrlAddress() on URL %s\r\n. Error code %d",
                            S3_PRESIGNED_URL,
                            httpStatus ) );
                returnStatus = EXIT_FAILURE;
            }
        }

        /**************************** Connect. ******************************/

        /* Establish TLS connection on top of TCP connection using OpenSSL. */
        if( returnStatus == EXIT_SUCCESS )
        {
            /* Attempt to connect to the HTTP server. If connection fails, retry after
             * a timeout. Timeout value will be exponentially increased till the maximum
             * attempts are reached or maximum timeout value is reached. The function
             * returns EXIT_FAILURE if the TCP connection cannot be established to
             * broker after configured number of attempts. */
            returnStatus = connectToServerWithBackoffRetries( connectToServer,
                                                              &networkContext );

            if( returnStatus == EXIT_FAILURE )
            {
                /* Log error to indicate connection failure after all
                 * reconnect attempts are over. */
                LogError( ( "Failed to connect to HTTP server %s.",
                            serverHost ) );
            }
        }

        /* Define the transport interface. */
        if( returnStatus == EXIT_SUCCESS )
        {
            transportInterface.recv = Openssl_Recv;
            transportInterface.send = Openssl_Send;
            transportInterface.pNetworkContext = &networkContext;
        }

        /******************** Start queues and HTTP task. *******************/

        /* Start request and response queues */
        if( returnStatus == EXIT_SUCCESS )
        {
            queueSettings.mq_maxmsg = 10;
            queueSettings.mq_msgsize = sizeof( RequestItem_t );

            requestQueue = mq_open( REQUEST_QUEUE,
                                    O_CREAT | O_WRONLY,
                                    0700,
                                    &queueSettings );

            queueSettings.mq_msgsize = sizeof( ResponseItem_t );

            responseQueue = mq_open( RESPONSE_QUEUE,
                                     O_CREAT | O_RDONLY,
                                     0700,
                                     &queueSettings );

            if( requestQueue == -1 )
            {
                LogError( ( "Failed to open request queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }

            if( responseQueue == -1 )
            {
                LogError( ( "Failed to open response queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }
        }

        /* Start HTTP task */

        if( returnStatus == EXIT_SUCCESS )
        {
            httpThread = startHTTPThread( &transportInterface );

            if( httpThread == -1 )
            {
                returnStatus = EXIT_SUCCESS;
            }
        }

        /******************** Download S3 Object File. **********************/
        if( returnStatus == EXIT_SUCCESS )
        {
            returnStatus = requestS3ObjectFile( serverHost,
                                                HTTP_METHOD_GET,
                                                pPath,
                                                requestQueue,
                                                &requestCount );
        }

        if( returnStatus == EXIT_SUCCESS )
        {
            retrieveS3ObjectFile( responseQueue, &requestCount );
        }

        /************************** Disconnect. *****************************/

        /* End TLS session, then close TCP connection. */
        ( void ) Openssl_Disconnect( &networkContext );

        /******************** Clean up queues and HTTP task. ****************/

        /* End http task */
        if( httpThread != -1 )
        {
            kill( httpThread, SIGTERM );
        }

        /* Close and delete the queues */
        if( requestQueue != -1 )
        {
            if( mq_close( requestQueue ) == -1 )
            {
                LogError( ( "Failed to close request queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }

            if( mq_unlink( REQUEST_QUEUE ) == -1 )
            {
                LogError( ( "Failed to delete request queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }
        }

        if( responseQueue != -1 )
        {
            if( mq_close( responseQueue ) == -1 )
            {
                LogError( ( "Failed to close response queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }

            if( mq_unlink( RESPONSE_QUEUE ) == -1 )
            {
                LogError( ( "Failed to delete response queue with error %s.",
                            strerror( errno ) ) );
                returnStatus = EXIT_FAILURE;
            }
        }

        LogInfo( ( "Short delay before starting the next iteration....\n" ) );
        sleep( DEMO_LOOP_DELAY_SECONDS );
    }

    return returnStatus;
}
