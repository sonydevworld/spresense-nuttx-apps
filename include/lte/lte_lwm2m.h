/****************************************************************************
 * apps/include/lte/lte_lwm2m.h
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#ifndef __APPS_INCLUDE_LTE_LTE_LWM2M_H
#define __APPS_INCLUDE_LTE_LTE_LWM2M_H

/**
 * @file lte_lwm2m.h
 * @brief LwM2M API definitions provided by Modem.
 *
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdint.h>
#include <nuttx/wireless/lte/lte.h>

/**
 * @defgroup lte_lwm2m LTE LwM2M API definitions
 * @ingroup lte
 * @brief LTE LwM2M API Definitions.
 * @{
 */

/** @defgroup ltelwm2m_macro_reshandle */
/** @defgroup ltelwm2m_macro_maxsizes */
/** @defgroup ltelwm2m_macro_condvalid */
/** @defgroup ltelwm2m_macro_fwupnote */
/** @defgroup ltelwm2m_macro_command */
/** @defgroup ltelwm2m_macro_serverstat */
/** @defgroup ltelwm2m_macro_resopmode */
/** @defgroup ltelwm2m_macro_resinsttype */
/** @defgroup ltelwm2m_macro_resdatatype */
/** @defgroup ltelwm2m_macro_seqmode */
/** @defgroup ltelwm2m_macro_regcmd */
/** @defgroup ltelwm2m_macro_respcode */
/** @defgroup ltelwm2m_macro_serverop */
/** @defgroup ltelwm2m_callback_functypes */
/** @defgroup ltelwm2m_func_beforeradioon */
/** @defgroup ltelwm2m_func_afterradioon */

/** @name Identifiers of Resource Handling Side
 *  @brief Resource handling side identifier which is set on handl member in @ref lwm2mstub_resource_s
 * @{
 */
/** @addtogroup ltelwm2m_macro_reshandle
 * @{
 */
/** @brief The resource handling is not cared
 *  This parameter set on handl member when you don't change it by @ref lte_setm2m_objectdefinition */
#define LWM2MSTUB_RESOURCE_HANDLENOCARE (0)
/** @brief The resource is handled by host side */
#define LWM2MSTUB_RESOURCE_HANDLEHOST   (1)
/** @brief The resource is not handled */
#define LWM2MSTUB_RESOURCE_HANDLEMODEMH (2)
/** @} */ /* end of group m2m_handlid */
/** @} */

/** @name Max size definitions
 *  @brief Several max size definitions
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_maxsizes
 * @{ */
/** @brief Max size of write data */
#define LWM2MSTUB_MAX_WRITE_SIZE (1500)
/** @brief Max size of observation token */
#define LWM2MSTUB_MAX_TOKEN_SIZE (8 * 2 + 1)
/** @brief Max server name length in @ref lwm2mstub_serverinfo_s */
#define LWM2MSTUB_MAX_SERVER_NAME (256)
/** @brief Max device id length in @ref lwm2mstub_serverinfo_s */
#define LWM2MSTUB_MAX_DEVID       (256)
/** @brief Max security key length in @ref lwm2mstub_serverinfo_s */
#define LWM2MSTUB_MAX_SEQKEY      (256)
/** @} */
/** @} */

/** @name Valid field bit map definitions
 *  @brief Bit position of valid_mask in @ref lwm2mstub_ovcondition_s 
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_condvalid
 * @{ */
/** @brief Bit position of min_period
 *  If this bit is set in valid_mask on @ref lwm2mstub_ovcondition_s, min_period field has valid information */
#define LWM2MSTUB_CONDVALID_MINPERIOD  (1<<0)
/** @brief Bit position of min_period
 *  If this bit is set in valid_mask on @ref lwm2mstub_ovcondition_s, max_period field has valid information */
#define LWM2MSTUB_CONDVALID_MAXPERIOD  (1<<1)
/** @brief Bit position of gt_cond
 *  If this bit is set in valid_mask on @ref lwm2mstub_ovcondition_s, gt_cond field has valid information */
#define LWM2MSTUB_CONDVALID_GRATERTHAN (1<<2)
/** @brief Bit position of lt_cond
 *  If this bit is set in valid_mask on @ref lwm2mstub_ovcondition_s, lt_cond field has valid information */
#define LWM2MSTUB_CONDVALID_LESSTHAN   (1<<3)
/** @brief Bit position of step_val
 *  If this bit is set in valid_mask on @ref lwm2mstub_ovcondition_s, step_val field has valid information */
#define LWM2MSTUB_CONDVALID_STEP       (1<<4)
/** @} */ /* end of group m2m_condvalid */
/** @} */

/** @name Firmware update notifies
 *  @brief Event to notice when firmware update reporting by @ref lwm2mstub_fwupstate_cb_t callback
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_fwupnote
 * @{ */
/** @brief Downloading firmware image is pending */
#define LWM2MSTUB_FWUP_PEND_DL  (0)
/** @brief Updating downloaded firmware is pending */
#define LWM2MSTUB_FWUP_PEND_UPD (1)
/** @brief Downloading firmware image is completed */
#define LWM2MSTUB_FWUP_COMP_DL  (2)
/** @brief Failed the downloading firmware */
#define LWM2MSTUB_FWUP_FAIL_DL  (3)
/** @brief Firmware updating is canceled by server*/
#define LWM2MSTUB_FWUP_CANCELED (4)
/** @} */ /* end of group m2m_fwupnote */
/** @} */

/** @name DISCARD: Registration command code
 *  @brief Those parameter is discarded. Those will be removed. Strong recommend to use @ref ltelwm2m_macro_regcmd
 * @{ */
/**
 *  @addtogroup ltelwm2m_macro_command
 * @{ */
/** @brief Register to a server */
#define LWM2MSTUB_CMD_REGISTER      (0)
/** @brief De-register from a server */
#define LWM2MSTUB_CMD_DEREGISTER    (1)
/** @brief Update registration to a server */
#define LWM2MSTUB_CMD_UPDATERESIGER (2)
/** @} */ /* end of group m2m_command */
/** @} */

/** @name Current server state
 *  @brief Current server status
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_serverstat
 * @{ */
/** @brief This device is not registered */
#define LWM2MSTUB_STATE_NOTREGISTERD    (0)
/** @brief Registering is pending */
#define LWM2MSTUB_STATE_REGISTPENDING   (1)
/** @brief This device is registered */
#define LWM2MSTUB_STATE_REGISTERD       (2)
/** @brief Registration failed */
#define LWM2MSTUB_STATE_REGISTERFAILED  (3)
/** @brief Registration updating */
#define LWM2MSTUB_STATE_UPDATEPENDING   (4)
/** @brief De-registering */
#define LWM2MSTUB_STATE_DEREGISTPENDING (5)
/** @brief Bootstrap hold off */
#define LWM2MSTUB_STATE_BSHOLDOFF       (6)
/** @brief Bootstrap is requested */
#define LWM2MSTUB_STATE_BSREQUESTED     (7)
/** @brief Bootstrap is on going */
#define LWM2MSTUB_STATE_BSONGOING       (8)
/** @brief Bootstrap is done */
#define LWM2MSTUB_STATE_BSDONE          (9)
/** @brief Bootstrap is failed */
#define LWM2MSTUB_STATE_BSFAILED        (10)
/** @} */ /* end of group m2m_serverstat */
/** @} */

/** @name Resource operation mode
 *  @brief Resource operation mode which is set on operation member in @ref lwm2mstub_resource_s
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_resopmode
 * @{ */
/** @brief The resource is "READ" operation */
#define LWM2MSTUB_RESOP_READ  (0)
/** @brief The resource is "WRITE" operation */
#define LWM2MSTUB_RESOP_WRITE (1)
/** @brief The resource is "READ and WRITE" operation */
#define LWM2MSTUB_RESOP_RW    (2)
/** @brief The resource is "EXECUTE" operation */
#define LWM2MSTUB_RESOP_EXEC  (3)
/** @} */ /* end of group m2m_resopmode */
/** @} */

/** @name Resource instance type
 *  @brief Resource multiple/single type which is set on inst_type member in @ref lwm2mstub_resource_s
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_resinsttype
 * @{ */
/** @brief The resource is "SINGLE" instance */
#define LWM2MSTUB_RESINST_SINGLE (0)
/** @brief The resource is "MULTIPLE" instance */
#define LWM2MSTUB_RESINST_MULTI  (1)
/** @} */ /* end of group m2m_resinsttype */
/** @} */

/** @name Resource data type
 *  @brief Resource data type which is set on data_type member in @ref lwm2mstub_resource_s
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_resdatatype
 * @{ */
/** @brief The resource data type is "NONE" */
#define LWM2MSTUB_RESDATA_NONE     (0)
/** @brief The resource data type is "String" */
#define LWM2MSTUB_RESDATA_STRING   (1)
/** @brief The resource data type is "Integer" */
#define LWM2MSTUB_RESDATA_INT      (2)
/** @brief The resource data type is "Unsigned integer" */
#define LWM2MSTUB_RESDATA_UNSIGNED (3)
/** @brief The resource data type is "Float" */
#define LWM2MSTUB_RESDATA_FLOAT    (4)
/** @brief The resource data type is "Boolean" */
#define LWM2MSTUB_RESDATA_BOOL     (5)
/** @brief The resource data type is "Opaque" */
#define LWM2MSTUB_RESDATA_OPAQUE   (6)
/** @brief The resource data type is "Time" */
#define LWM2MSTUB_RESDATA_TIME     (7)
/** @brief The resource data type is "Object Link" */
#define LWM2MSTUB_RESDATA_OBJLINK  (8)
/** @} */ /* end of group m2m_resdatatype */
/** @} */

/** @name Secure mode type
 *  @brief Secure mode type
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_seqmode
 * @{ */
/** @brief The secure mode is "PSK" */
#define LWM2MSTUB_SECUREMODE_PSK     (0)
/** @brief The secure mode is "RSK" */
#define LWM2MSTUB_SECUREMODE_RPK     (1)
/** @brief The secure mode is "CERT" */
#define LWM2MSTUB_SECUREMODE_CERT    (2)
/** @brief The secure mode is "Non secure" */
#define LWM2MSTUB_SECUREMODE_NOSEC   (3)
/** @brief The secure mode is "CERTEST" */
#define LWM2MSTUB_SECUREMODE_CERTEST (4)
/** @} */ /* end of group m2m_seqmode */
/** @} */

/** @name Registration command code
 *  @brief Secure mode type
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_regcmd
 * @{ */
/** @brief Registration start command */
#define LWM2MSTUB_CONNECT_REGISTER   (0)
/** @brief De-registration start command */
#define LWM2MSTUB_CONNECT_DEREGISTER (1)
/** @brief Re-registration start command */
#define LWM2MSTUB_CONNECT_REREGISTER (2)
/** @brief Bootstrap start command */
#define LWM2MSTUB_CONNECT_BOOTSTRAP  (3)
/** @} */ /* end of group m2m_regcmd */
/** @} */

/** @name Response code for server operation
 *  @brief Secure mode type
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_respcode
 * @{ */
/** @brief The request is accepted and the parameter changed */
#define LWM2MSTUB_RESP_CHANGED       (0)
/** @brief The request is to context */
#define LWM2MSTUB_RESP_CONTENT       (1)
/** @brief The request is bad request */
#define LWM2MSTUB_RESP_BADREQ        (2)
/** @brief The request is not authorized */
#define LWM2MSTUB_RESP_UNAUTH        (3)
/** @brief The request URI doesn't exist */
#define LWM2MSTUB_RESP_NOURI         (4)
/** @brief The request is not allowed */
#define LWM2MSTUB_RESP_NOTALLOW      (5)
/** @brief The request is not accepted */
#define LWM2MSTUB_RESP_NOTACCEPT     (6)
/** @brief The request is not supported */
#define LWM2MSTUB_RESP_UNSUPPORT     (7)
/** @brief Internal error is occurred then the request received */
#define LWM2MSTUB_RESP_INTERNALERROR (8)
/** @} */ /* end of group m2m_respcode */
/** @} */

/** @name Server operation notification
 *  @brief Server operation code reported by @ref lwm2mstub_fwupstate_cb_t callback
 * @{ */
/**
 * @addtogroup ltelwm2m_macro_serverop
 * @{ */
/** @brief Client received "Write" operation */
#define LWM2MSTUB_OP_WRITE      (0)
/** @brief Client received "Execute" operation */
#define LWM2MSTUB_OP_EXEC       (1)
/** @brief Client received "Write Attributes" operation */
#define LWM2MSTUB_OP_WATTR      (4)
/** @brief Client received "Discover" operation */
#define LWM2MSTUB_OP_DISCOVER   (5)
/** @brief Client received "Read" operation */
#define LWM2MSTUB_OP_READ       (6)
/** @brief Client received "Observe" operation */
#define LWM2MSTUB_OP_OBSERVE    (7)
/** @brief Client received "Cancel observation" operation */
#define LWM2MSTUB_OP_CANCELOBS  (8)
/** @brief Client is offline now. */
#define LWM2MSTUB_OP_OFFLINE    (9)
/** @brief Client is online now. */
#define LWM2MSTUB_OP_ONLINE     (10)
/** @brief Client sent observation notification to a server. */
#define LWM2MSTUB_OP_SENDNOTICE (11)
/** @brief Client received wakeup SMS. */
#define LWM2MSTUB_OP_RCVWUP     (12)
/** @brief Client received notification acknowledge. */
#define LWM2MSTUB_OP_RCVOBSACK  (13)
/** @brief Client ON: LMM2M client exits Client OFF state
 * and tries to re-connect server
 */
#define LWM2MSTUB_OP_CLIENTON   (14)
/** @brief Client OFF: LWM2M client has exhausted server connection retries. */
#define LWM2MSTUB_OP_CLIENTOFF  (15)
/** @brief Confirmable NOTIFY failed. */
#define LWM2MSTUB_OP_FAILNOTIFY  (16)
/** @brief Bootstrap finished and completed successfully. */
#define LWM2MSTUB_OP_BSFINISH  (20)
/** @brief Registration finished and completed successfully.
 * all server observation requests are cleaned,
 * the host should clean host objects observation rules too.
 */
#define LWM2MSTUB_OP_REGSUCCESS  (21)
/** @brief Register update finished and completed successfully. */
#define LWM2MSTUB_OP_REGUPDATED  (22)
/** @brief De-register finished and completed successfully. */
#define LWM2MSTUB_OP_DEREGSUCCESS  (23)
/** @brief Notification was not saved and not sent to server */
#define LWM2MSTUB_OP_NOSENDNOTICE  (24)
/** @} */ /* end of group m2m_serverop */
/** @} */

/**
 * Structure for resource information
 * Used on @ref lte_getm2m_objresourceinfo and @ref lte_setm2m_objectdefinition
 */
struct lwm2mstub_resource_s
{
  int res_id;     /**< Resource id */
  int operation;  /**< Operation mode: refer to @ref ltelwm2m_macro_resopmode more details */
  int inst_type;  /**< Instance type: refer to @ref ltelwm2m_macro_resinsttype more details */ 
  int data_type;  /**< Data type: refer to @ref ltelwm2m_macro_resdatatype more details */
  int handl;      /**< Handle side: refer to @ref ltelwm2m_macro_reshandle more details */
};

/**
 * Structure for instance URI
 * Used on @ref ltelwm2m_macro_callbacks and @ref ltelwm2m_macro_responses
 */
struct lwm2mstub_instance_s
{
  int object_id;    /**< Object ID */
  int object_inst;  /**< Object Instance number */
  int res_id;       /**< Resource ID */
  int res_inst;     /**< Resource instance number */
};

/**
 * Structure for observe condition information
 * Used on @ref lwm2mstub_ovstart_cb_t
 */
struct lwm2mstub_ovcondition_s
{
    uint8_t valid_mask;       /**< Bit map to indicate valid parameters: refer to @ref ltelwm2m_macro_condvalid for more details */
    unsigned int min_period;  /**< Min period seconds */
    unsigned int max_period;  /**< Max period seconds */
    double gt_cond;           /**< Grater than condition */
    double lt_cond;           /**< Less than condition */
    double step_val;          /**< Step value */
};

/**
 * Structure for server information
 * Used on @ref lte_setm2m_serverinfo and @ref lte_getm2m_serverinfo
 */
struct lwm2mstub_serverinfo_s
{
  int object_inst;    /**< Server object instance number. Usually set to 0 */
  int state;          /**< Current server status: Refer to @ref ltelwm2m_macro_serverstat for more details */
  bool bootstrap;     /**< Set true, when it uses bootstrap server */
  bool nonip;         /**< Set true, when Non IP like NIDD is used */
  int security_mode;  /**< Security type: Refer to @ref ltelwm2m_macro_seqmode for more details */
  char server_uri[LWM2MSTUB_MAX_SERVER_NAME]; /**< Server URI */
  char device_id[LWM2MSTUB_MAX_DEVID];        /**< Device ID */
  char security_key[LWM2MSTUB_MAX_SEQKEY];    /**< Security key */
};

/**
 * @name Callback function types
 * @brief Callback function types to receive notification from server.
 * @{ */
/**
 * @addtogroup ltelwm2m_callback_functypes
 * @{ */
/**
 * @brief Write request call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2mwrite to get write request from the server
 *
 * @param [in] seq_no: Request sequence number generated by modem. This number is used when the response is sent.
 * @param [in] srv_id: Server ID which is received the request.
 * @param [in] inst: Requested resource url.
 * @param [in] value: Written value as string data.
 * @param [in] len: Length of the value.
 */
typedef void (*lwm2mstub_write_cb_t)(int seq_no, int srv_id,
              struct lwm2mstub_instance_s *inst, char *value, int len);

/**
 * @brief Read request call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2mread to get read request from the server
 *
 * @param [in] seq_no: Request sequence number generated by modem. This number is used when the response is sent.
 * @param [in] srv_id: Server ID which is received the request.
 * @param [in] inst: Requested resource url.
 */
typedef void (*lwm2mstub_read_cb_t)(int seq_no, int srv_id,
              struct lwm2mstub_instance_s *inst);

/**
 * @brief Execution request call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2mexec to get execution request from the server
 *
 * @param [in] seq_no: Request sequence number generated by modem. This number is used when the response is sent.
 * @param [in] srv_id: Server ID which is received the request.
 * @param [in] inst: Requested resource url.
 */
typedef void (*lwm2mstub_exec_cb_t)(int seq_no, int srv_id,
              struct lwm2mstub_instance_s *inst);

/**
 * @brief Observe start request call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2movstart to get observation start request from the server
 *
 * @param [in] seq_no: Request sequence number generated by modem. This number is used when the response is sent.
 * @param [in] srv_id: Server ID which is received the request.
 * @param [in] inst: Requested resource url.
 * @param [in] token: Token ID for this observation. This token is used when it updates the value by @ref lte_m2m_observeupdate
 * @param [in] cond: Observation condition
 */
typedef void (*lwm2mstub_ovstart_cb_t)(int seq_no, int srv_id,
              struct lwm2mstub_instance_s *inst, char *token,
              struct lwm2mstub_ovcondition_s *cond);

/**
 * @brief Observation stop request call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2movstop to get write request from the server
 *
 * @param [in] seq_no: Request sequence number generated by modem. This number is used when the response is sent.
 * @param [in] srv_id: Server ID which is received the request.
 * @param [in] inst: Requested resource url.
 * @param [in] token: Token ID for the observation to stop.
 */
typedef void (*lwm2mstub_ovstop_cb_t)(int seq_no, int srv_id,
              struct lwm2mstub_instance_s *inst, char *token);

/**
 * @brief Server operation call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2moperation to get brief request code from the server
 *
 * @param [in] event: Operation code from Server. Refer to @ref ltelwm2m_macro_serverop for more details
 */
typedef void (*lwm2mstub_operation_cb_t)(int event);

/**
 * @brief Firmware update call back function type.
 *
 * This type of function pointer is registered by @ref lte_set_report_m2mfwupdate to get the status of firmware update
 *
 * @param [in] event: Status code about firmware update. Refer to @ref ltelwm2m_callback_functypes for more details
 */
typedef void (*lwm2mstub_fwupstate_cb_t)(int event);
/** @} */
/** @} */

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* On powe on state */

/**
 * @name Functions before Radio ON
 * @brief API functions which can effect before @ref lte_radio_on()
 *
 * Those functions can be called just after @ref lte_power_on() until before @ref lte_radio_on().
 * @{ */
/**
 * @addtogroup ltelwm2m_func_beforeradioon
 * @{ */
/**
 * @brief Set endpoint name
 *
 * To set the device endpoint name.
 * @param [in] name: Endpoint name to set. This is ASCII character array terminated by '\0'
 * @retval OK Setting is done successfully 
 * @retval non-OK  Any error is occurred
 */
int lte_setm2m_endpointname(FAR char *name);

/**
 * @brief Get endpoint name
 *
 * Get the device endpoint name.
 * @param [out] name: pointer to store the endpoint name.
 * @param [in] len: Length of the memory of name in bytes.
 * @retval OK Setting is done successfully 
 * @retval non-OK  Any error is occurred
 */
int lte_getm2m_endpointname(FAR char *name, int len);

/**
 * @brief Get Server num
 *
 * Get number of servers.
 * @retval >=0 Server number
 * @retval <0  Any error is occurred
 */
int lte_getm2m_servernum(void);

/**
 * @brief Server configuration
 *
 * Configure the settings according to the information on the server side.
 * @param [in] info: Server information to set
 * @param [in] id: Server ID. Which is an ID from 0 to the number obtained by @ref lte_getm2m_servernum(). Currently only 0 is supported.
 * @retval OK Configuration is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_setm2m_serverinfo(FAR struct lwm2mstub_serverinfo_s *info, int id);

/**
 * @brief Get server configuration
 *
 * Configure the settings according to the information on the server side.
 * @param [out] info: Server information
 * @param [in] id: Server ID. Which is an ID from 0 to the number obtained by @ref lte_getm2m_servernum(). Currently only 0 is supported.
 * @retval OK Configuration is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_getm2m_serverinfo(FAR struct lwm2mstub_serverinfo_s *info, int id);

/**
 * @brief Get enabled objects number
 *
 * Obtaining the number of currently active objects.
 * @retval >=0 Objects number
 * @retval <0  Any error is occurred
 */
int lte_getm2m_enabled_objectnum(void);

/**
 * @brief Get object IDs of currently active objects
 *
 * Obtaining object IDs of currently active objects.
 * @param [out] objids: Array to store object IDs
 * @param [in] objnum: Size of objids array
 * @retval >=0 Actual number of object IDs
 * @retval <0  Any error is occurred
 */
int lte_getm2m_enabled_objects(uint16_t *objids, int objnum);

/**
 * @brief Enable objects
 *
 * Activate the specified Object IDs
 * @param [in] objids: Array to indicate object IDs to enable
 * @param [in] objnum: Size of objids array
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_enablem2m_objects(uint16_t *objids, int objnum);

/**
 * @brief Get resource number on the object
 *
 * Obtains the number of resources that the specified Object has.
 * @param [in] objid: Object ID
 * @retval >=0 The number of resources
 * @retval <0  Any error is occurred
 */
int lte_getm2m_objresourcenum(uint16_t objid);

/**
 * @brief Get the information of resources on the object
 *
 * Obtains the information of resources that the specified Object has.
 * @param [in] objids: Object ID
 * @param [in] res_num: Array size of reses
 * @param [in] reses: Array of resources information to store
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_getm2m_objresourceinfo(uint16_t objids, int res_num,
                                struct lwm2mstub_resource_s *reses);

/**
 * @brief Configure the resources of the object
 *
 * Configure the resources specified the object.
 * @param [in] objids: Object ID
 * @param [in] res_num: Array size of reses
 * @param [in] reses: Array of resources to configure
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_setm2m_objectdefinition(uint16_t objids, int res_num,
                                struct lwm2mstub_resource_s *reses);

/**
 * @brief Activate all configurations
 *
 * Configuration functions in @ref ltelwm2m_func_beforeradioon group is not effected before this function is called.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_apply_m2msetting(void);
/** @} */
/** @} */

/* After attached */

/**
 * @name Functions after Radio ON
 * @brief API functions which can effect after @ref lte_radio_on()
 *
 * Those functions can be called after @ref lte_radio_on().
 * @{ */
/**
 * @addtogroup ltelwm2m_func_afterradioon
 * @{ */

/**
 * @brief Control connection to server
 *
 * Connection control to the server which is configured by @ref lte_setm2m_serverinfo()
 * @param [in] cmd: Connection command. Refer to @ref ltelwm2m_macro_regcmd for more details.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_connection(int cmd);

/**
 * @brief Register callback function pointer for write request
 *
 * Register callback function to get notification of  write request from a server
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2mwrite(lwm2mstub_write_cb_t cb);

/**
 * @brief Register callback function pointer for read request
 *
 * Register callback function to get notification of  read request from a server
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2mread(lwm2mstub_read_cb_t cb);

/**
 * @brief Register callback function pointer for execute request
 *
 * Register callback function to get notification of execute request from a server
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2mexec(lwm2mstub_exec_cb_t cb);

/**
 * @brief Register callback function pointer for observation start request
 *
 * Register callback function to get notification of observation start request from a server
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2movstart(lwm2mstub_ovstart_cb_t cb);

/**
 * @brief Register callback function pointer for observation stop request
 *
 * Register callback function to get notification of observation stop request from a server
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2movstop(lwm2mstub_ovstop_cb_t cb);

/**
 * @brief Register callback function pointer for server operation
 *
 * Register callback function to get briefly notification of server operation
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2moperation(lwm2mstub_operation_cb_t cb);

/**
 * @brief Register callback function pointer for firmware update status
 *
 * Register callback function to get notification of firmware update status from the modem
 * @param [in] cb: Callback function pointer which is implemented by user
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_set_report_m2mfwupdate(lwm2mstub_fwupstate_cb_t cb);

/**
 * @brief Response result of read request to the server
 *
 * Send response of result of read request to the server.
 * Basically this function is called in @ref lwm2mstub_read_cb_t callback function.
 * @param [in] seq_no: Sequence number provided on an argument as seq_no in @ref lwm2mstub_read_cb_t
 * @param [in] inst: Resource URI to respond. Basically this should be the same as inst argument on @ref lwm2mstub_read_cb_t
 * @param [in] resp: Response code. Refer to @ref ltelwm2m_macro_serverop for more details.
 * @param [in] value: Read value as string data to send.
 * @param [in] len: Length of the value.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_readresponse(int seq_no,
                         FAR struct lwm2mstub_instance_s *inst,
                         int resp, char *readvalue, int len);

/**
 * @brief Response result of write request to the server
 *
 * Send response of result of write request to the server.
 * Basically this function is called in @ref lwm2mstub_write_cb_t callback function.
 * @param [in] seq_no: Sequence number provided on an argument as seq_no in @ref lwm2mstub_write_cb_t
 * @param [in] inst: Resource URI to respond. Basically this should be the same as inst argument on @ref lwm2mstub_write_cb_t
 * @param [in] resp: Response code. Refer to @ref ltelwm2m_macro_serverop for more details.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_writeresponse(int seq_no,
                          FAR struct lwm2mstub_instance_s *inst,
                          int resp);

/**
 * @brief Response result of execute request to the server
 *
 * Send response of result of execute request to the server.
 * Basically this function is called in @ref lwm2mstub_exec_cb_t callback function.
 * @param [in] seq_no: Sequence number provided on an argument as seq_no in @ref lwm2mstub_exec_cb_t
 * @param [in] inst: Resource URI to respond. Basically this should be the same as inst argument on @ref lwm2mstub_exec_cb_t
 * @param [in] resp: Response code. Refer to @ref ltelwm2m_macro_serverop for more details.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_executeresp(int seq_no,
                        FAR struct lwm2mstub_instance_s *inst,
                        int resp);

/**
 * @brief Response result of observation start/stop request to the server
 *
 * Send response of result of observation start/stop request to the server.
 * Basically this function is called in @ref lwm2mstub_obstart_cb_t or @ref lwm2mstub_ovstop_cb_t callback function.
 * @param [in] seq_no: Sequence number provided on an argument as seq_no in @ref lwm2mstub_ovstart_cb_t or @ref lwm2mstub_ovstop_cb_t
 * @param [in] resp: Response code. Refer to @ref ltelwm2m_macro_serverop for more details.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_observeresp(int seq_no, int resp);

/**
 * @brief Update observation data to the server
 *
 * Send update data of observation resource to the server.
 * @param [in] token: Token code that is identify the observation. This is provided by @ref lwm2mstub_ovstart_cb_t as an argument named token.
 * @param [in] inst: Resource URI to update.
 * @param [in] value: Update value as string data to send.
 * @param [in] len: Length of the value.
 * @retval OK Operation is done successfully
 * @retval non-OK  Any error is occurred
 */
int lte_m2m_observeupdate(char *token,
                          FAR struct lwm2mstub_instance_s *inst,
                          char *value, int len);
/** @} */
/** @} */

#ifdef __cplusplus
}
#endif

/** @} */ /* end of group lte_lwm2m */

#endif  /* __APPS_INCLUDE_LTE_LTE_LWM2M_H */
