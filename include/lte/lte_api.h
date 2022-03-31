/****************************************************************************
 * apps/include/lte/lte_api.h
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

#ifndef __APPS_INCLUDE_LTE_LTE_API_H
#define __APPS_INCLUDE_LTE_LTE_API_H

/**
 * @defgroup lte LTE Library API
 * @brief LTE library for using LTE network
 *
 * - Abbreviations and terms
 *  - PDN : Packet Data Network
 *
 *      Route for transferring packets between the terminal and LTE networks.
 *
 *  - APN : Access Point Name
 *
 *      Settings required when connecting to an LTE network.
 *
 *  - IMSI : International Mobile Subscriber Identity
 *
 *      International subscriber identification number recorded
 *      on the SIM card.
 *
 *  - IMEI : International Mobile Equipment Identifier
 *
 *      International identification number assigned to
 *      data communication terminals
 *
 *  - PIN : Personal Identification Number
 *
 *  - MCC : Mobile Country Code
 *
 *      The mobile country code consists of three decimal digits.
 *
 *  - MNC : Mobile Network Code
 *
 *      The mobile network code consists of two or three decimal digits.
 *
 *  - eDRX : extended Discontinuous Reception
 *
 *      Communication technology that reduces power consumption
 *      by increasing the reception interval of various signals transmitted
 *      from LTE networks.
 *
 *  - PSM : Power Saving Mode
 *
 *      Communication technology that reduces power consumption
 *      by not communicating with the LTE network
 *      for a certain period of time.
 *
 *  - CE : Coverage Enhancement
 *
 *      Communication technology that attempts to resend data and eventually
 *      restores the original data even if the data is corrupted
 *      due to weak electric field communication.
 *
 *  - RAT : Radio Access Technology
 *
 *      Physical connection method for a radio based communication network.
 *
 * - LTE API system
 *  - Network connection API
 *
 *      Radio ON / OFF, PDN connection establishment / destruction.
 *
 *  - Communication quality and communication state API
 *
 *      Acquisition of radio status, communication status, and local time.
 *
 *  - SIM card control API
 *
 *      Get phone number / IMSI, set the PIN, get SIM status.
 *
 *  - Modem setting API
 *
 *      Get modem firmware version and IMEI. Update communication settings.
 *
 * - API call type
 *
 *      There are two types of LTE API: synchronous and asynchronous.
 *
 *  - Synchronous API
 *    - Notifies the processing result as a return value.
 *
 *    - Blocks the task that called the API until
 *      processing is completed on the modem.
 *
 *    - If the return value is -EPROTO, you can get the error code
 *      with lte_get_errinfo.
 *
 *    - If the argument attribute is out, the argument must be allocated
 *      by the caller.
 *
 *  - Asynchronous API
 *    - The processing result is notified by callback.
 *      The callback is invoked in the task context.
 *
 *    - Blocks the task that called the API until it requests
 *      processing from the modem.
 *
 *    - Notifies the processing request result as a return value.
 *
 *    - The callback is registered with the argument of each API.
 *      Registration is canceled when the processing result is notified.
 *
 *    - The same API cannot be called until the processing result is notified
 *      by the callback.(-EINPROGRESS is notified with a return value.)
 *
 *    - If the callback reports an error (LTE_RESULT_ERROR),
 *      detailed error information can be acquired with lte_get_errinfo.
 *
 *  For some APIs, both synchronous and asynchronous APIs are available.
 *  The correspondence table of API is as follows.
 *
 *
 * | Synchronous API              | Asynchronous API           |
 * | ---------------------------- | -------------------------- |
 * | lte_initialize               |                            |
 * | lte_finalize                 |                            |
 * | lte_set_report_restart       |                            |
 * | lte_power_on                 |                            |
 * | lte_power_off                |                            |
 * | lte_set_report_netinfo       |                            |
 * | lte_set_report_simstat       |                            |
 * | lte_set_report_localtime     |                            |
 * | lte_set_report_quality       |                            |
 * | lte_set_report_cellinfo      |                            |
 * | lte_get_errinfo              |                            |
 * | lte_activate_pdn_cancel      |                            |
 * | lte_radio_on_sync            | lte_radio_on               |
 * | lte_radio_off_sync           | lte_radio_off              |
 * | lte_activate_pdn_sync        | lte_activate_pdn           |
 * | lte_deactivate_pdn_sync      | lte_deactivate_pdn         |
 * | lte_data_allow_sync          | lte_data_allow             |
 * | lte_get_netinfo_sync         | lte_get_netinfo            |
 * | lte_get_imscap_sync          | lte_get_imscap             |
 * | lte_get_version_sync         | lte_get_version            |
 * | lte_get_phoneno_sync         | lte_get_phoneno            |
 * | lte_get_imsi_sync            | lte_get_imsi               |
 * | lte_get_imei_sync            | lte_get_imei               |
 * | lte_get_pinset_sync          | lte_get_pinset             |
 * | lte_set_pinenable_sync       | lte_set_pinenable          |
 * | lte_change_pin_sync          | lte_change_pin             |
 * | lte_enter_pin_sync           | lte_enter_pin              |
 * | lte_get_localtime_sync       | lte_get_localtime          |
 * | lte_get_operator_sync        | lte_get_operator           |
 * | lte_get_edrx_sync            | lte_get_edrx               |
 * | lte_set_edrx_sync            | lte_set_edrx               |
 * | lte_get_psm_sync             | lte_get_psm                |
 * | lte_set_psm_sync             | lte_set_psm                |
 * | lte_get_ce_sync              | lte_get_ce                 |
 * | lte_set_ce_sync              | lte_set_ce                 |
 * | lte_get_siminfo_sync         | lte_get_siminfo            |
 * | lte_get_current_edrx_sync    | lte_get_current_edrx       |
 * | lte_get_current_psm_sync     | lte_get_current_psm        |
 * | lte_get_quality_sync         | lte_get_quality            |
 * | lte_get_cellinfo_sync        |                            |
 * | lte_get_rat_sync             |                            |
 * | lte_set_rat_sync             |                            |
 * | lte_get_ratinfo_sync         |                            |
 * | lte_acquire_wakelock         |                            |
 * | lte_release_wakelock         |                            |
 * | lte_send_atcmd_sync          |                            |
 * | lte_factory_reset_sync       |                            |
 *
 * @{
 * @file  lte_api.h
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <nuttx/wireless/lte/lte.h>

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/** @name Functions */
/** @{ */

/**
 * Initialize resources used in LTE API.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_initialize(void);

/**
 * Release resources used in LTE API.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_finalize(void);

/**
 * Register the callback to notify that the modem has started up.
 *
 * The callback will be invoked if the modem starts successfully
 * after calling lte_power_on. Some APIs have to wait until
 * this callback is invoked. If no wait, those API return
 * with an error. (-ENETDOWN)
 *
 * The callback is also invoked when the modem is restarted.
 * The cause of the restart can be obtained from the callback argument.
 *
 * This function must be called after lte_initialize.
 *
 * @attention Attention to the following 
 *   when @ref LTE_RESTART_MODEM_INITIATED is set.
 * - Asynchronous API callbacks for which results have not been 
 *   notified are canceled and becomes available.
 *
 * - The processing result of the synchronous API
 *   being called results in an error. (Return value is -ENETDOWN)
 *   The errno is ENETDOWN for the socket API.
 *
 * - It should close the socket by user application.
 *
 * @param [in] restart_callback: Callback function to notify that
 *                               modem restarted.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_restart(restart_report_cb_t restart_callback);

/**
 * Power on the modem.
 *
 * The callback which registered by lte_set_report_restart
 * will be invoked if the modem starts successfully.
 *
 * This function must be called after lte_set_report_restart.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_power_on(void);

/**
 * Power off the modem
 *
 * @attention Attention to the following when this API calling.
 * - For asynchronous API
 *   - callback is canceled.
 *
 * - For synchronous API
 *   - API returns with an error.
 *     - The return value is -ENETDOWN for the LTE API.
 *     - The errno is ENETDOWN for the socket API.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_power_off(void);

/**
 * With the radio on, to start the LTE network search.
 *
 * @attention Attention to the following when this API calling.
 * - If SIM is PIN locked, the result will be an error.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_radio_on_sync(void);

/**
 * With the radio on, to start the LTE network search.
 *
 * @attention Attention to the following when this API calling.
 * - If SIM is PIN locked, the result will be an error.
 *
 * @param [in] callback: Callback function to notify that
 *                       radio on is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_radio_on(radio_on_cb_t callback);

/**
 * Exit LTE network searches with the radio off.
 *
 * If this function is called when a PDN has already been constructed,
 * the PDN is discarded.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_radio_off_sync(void);

/**
 * Exit LTE network searches with the radio off.
 *
 * If this function is called when a PDN has already been constructed,
 * the PDN is discarded.
 *
 * @param [in] callback: Callback function to notify that
 *                       radio off is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_radio_off(radio_off_cb_t callback);

/**
 * Get LTE network information.
 *
 * @attention The maximum number of PDNs status areas must be allocated
 *            before calls this API.
 *
 * @param [in] pdn_num: Number of pdn_stat allocated by the user.
 *                      The range is from @ref LTE_PDN_SESSIONID_MIN to
 *                      @ref LTE_PDN_SESSIONID_MAX.
 *
 * @param [out] info: The LTE network information.
 *                    See @ref lte_netinfo_t
 *
 * @attention Immediately after successful PDN construction
 *            using lte_activate_pdn_sync() or lte_activate_pdn(),
 *            session information such as IP address
 *            may not be acquired correctly.
 *            If you want to use this API after successfully construction
 *            the PDN, wait at least 1 second before executing it.
 *            
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_netinfo_sync(uint8_t pdn_num, lte_netinfo_t *info);

/**
 * Get LTE network information.
 *
 * @param [in] callback: Callback function to notify that
 *                       get network information completed.
 *
 * @attention Immediately after successful PDN construction
 *            using lte_activate_pdn_sync() or lte_activate_pdn(),
 *            session information such as IP address
 *            may not be acquired correctly.
 *            If you want to use this API after successfully construction
 *            the PDN, wait at least 1 second before executing it.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_netinfo(get_netinfo_cb_t callback);

/**
 * Constructs a PDN with the specified APN settings.
 *
 * When constructs the initial PDN, 
 * LTE_APN_TYPE_IA must be set to the APN type. 
 *
 * When PDN construction is successful, 
 * an IP address is given from the LTE network.
 *
 * @attention Attention to the following when this API calling.
 * - The initial PDN construction may take a few minutes 
 *   depending on radio conditions.
 *
 * - If API is not returned, please check if the APN settings are correct.
 *
 * @param [in] apn: The pointer of the apn setting.
 *                  See @ref lte_apn_setting_t for valid parameters.
 *
 * @param [out] pdn: The construction PDN information. 
 *                   See @ref lte_pdn_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 * If canceling, -ECANCELED is returned.
 */

int lte_activate_pdn_sync(lte_apn_setting_t *apn, lte_pdn_t *pdn);

/**
 * Constructs a PDN with the specified APN settings.
 *
 * When constructs the initial PDN,
 * LTE_APN_TYPE_IA must be set to the APN type.
 *
 * When PDN construction is successful,
 * an IP address is given from the LTE network.
 *
 * @attention Attention to the following when this API calling.
 * - The initial PDN construction may take a few minutes 
 *   depending on radio conditions.
 *
 * - If the callback is not notified, please check
 *   if the APN settings are correct.
 *
 * @param [in] apn: The pointer of the apn setting.
 *                  See @ref lte_apn_setting_t for valid parameters.
 *
 * @param [in] callback: Callback function to notify that
 *                       PDN activation completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_activate_pdn(lte_apn_setting_t *apn, activate_pdn_cb_t callback);

/**
 * Cancel PDN construction.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_activate_pdn_cancel(void);

/**
 * Discard the constructed PDN.
 *
 * Discards the PDN corresponding to the session ID
 * obtained by lte_activate_pdn.
 *
 * When the discard process is successful, the IP address assigned to
 * the modem is released to the LTE network.
 *
 * @param [in] session_id: The numeric value of the session ID.
 *                         Use the value obtained by the lte_activate_pdn.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_deactivate_pdn_sync(uint8_t session_id);

/**
 * Discard the constructed PDN.
 *
 * Discards the PDN corresponding to the session ID
 * obtained by lte_activate_pdn.
 *
 * When the discard process is successful, the IP address assigned to
 * the modem is released to the LTE network.
 *
 * @param [in] session_id: The numeric value of the session ID.
 *                         Use the value obtained by the lte_activate_pdn.
 *
 * @param [in] callback: Callback function to notify that
 *                       LTE PDN deactivation completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_deactivate_pdn(uint8_t session_id, deactivate_pdn_cb_t callback);

/**
 * Allow or disallow to data communication for specified PDN.
 *
 * @attention This function is not supported.
 *
 * @param [in] session_id: The numeric value of the session ID.
 *                         Use the value obtained by the lte_activate_pdn.
 *
 * @param [in] allow: Allow or disallow to data communication for
 *                    all network. Definition is as below.
 *  - @ref LTE_DATA_ALLOW
 *  - @ref LTE_DATA_DISALLOW
 *
 * @param [in] roaming_allow: Allow or disallow to data communication for
 *                            roaming network. Definition is as below.
 *  - @ref LTE_DATA_ALLOW
 *  - @ref LTE_DATA_DISALLOW
 *
 * @return -EOPNOTSUPP is returned.
 */

int lte_data_allow_sync(uint8_t session_id, uint8_t allow,
                        uint8_t roaming_allow);

/**
 * Allow or disallow to data communication for specified PDN.
 *
 * @attention This function is not supported.
 *
 * @param [in] session_id: The numeric value of the session ID.
 *                         Use the value obtained by the lte_activate_pdn.
 *
 * @param [in] allow: Allow or disallow to data communication for
 *                    all network. Definition is as below.
 *  - @ref LTE_DATA_ALLOW
 *  - @ref LTE_DATA_DISALLOW
 *
 * @param [in] roaming_allow: Allow or disallow to data communication for
 *                            roaming network. Definition is as below.
 *  - @ref LTE_DATA_ALLOW
 *  - @ref LTE_DATA_DISALLOW
 *
 * @param [in] callback: Callback function to notify that
 *                       configuration has changed.
 *
 * @return -EOPNOTSUPP is returned.
 */

int lte_data_allow(uint8_t session_id, uint8_t allow,
                   uint8_t roaming_allow, data_allow_cb_t callback);

/**
 * Get whether the modem supports IMS or not.
 *
 * @param [out] imscap: The IMS capability.
 *                      As below value stored.
 *  - @ref LTE_ENABLE
 *  - @ref LTE_DISABLE
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_imscap_sync(bool *imscap);

/**
 * Get whether the modem supports IMS or not.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting IMS capability is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_imscap(get_imscap_cb_t callback);

/**
 * Acquires the FW version information of the modem.
 *
 * @param [out] version: The version information of the modem.
 *                        See @ref lte_version_t
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_version_sync(lte_version_t *version);

/**
 * Acquires the FW version information of the modem.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting the version is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_version(get_ver_cb_t callback);

/**
 * Get phone number from SIM.
 *
 * @param [out] phoneno: A character string indicating phone number.
 *                       It is terminated with '\0'.
 *                       The maximum number of phone number areas
 *                       must be allocated. See @ref LTE_PHONENO_LEN.
 * @param [in] len:      Length of the buffer for storing phone number.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
int lte_get_phoneno_sync(char *phoneno);
#else
int lte_get_phoneno_sync(char *phoneno, size_t len);
#endif

/**
 * Get phone number from SIM.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting the phone number is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_phoneno(get_phoneno_cb_t callback);

/**
 * Get International Mobile Subscriber Identity from SIM.
 *
 * @param [out] imsi: A character string indicating IMSI.
 *                    It is terminated with '\0'.
 *                    The maximum number of IMSI areas
 *                    must be allocated. See @ref LTE_IMSI_LEN.
 * @param [in] len:   Length of the buffer for storing IMSI.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
int lte_get_imsi_sync(char *imsi);
#else
int lte_get_imsi_sync(char *imsi, size_t len);
#endif

/**
 * Get International Mobile Subscriber Identity from SIM.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting IMSI is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_imsi(get_imsi_cb_t callback);

/**
 * Get International Mobile Equipment Identifier from the modem.
 *
 * @param [out] imei: A character string indicating IMEI.
 *                    It is terminated with '\0'.
 *                    The maximum number of IMEI areas
 *                    must be allocated. See @ref LTE_IMEI_LEN.
 * @param [in] len:   Length of the buffer for storing IMEI.
 *
 * On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
int lte_get_imei_sync(char *imei);
#else
int lte_get_imei_sync(char *imei, size_t len);
#endif

/**
 * Get International Mobile Equipment Identifier from the modem.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting IMEI is completed
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_imei(get_imei_cb_t callback);

/**
 * Get Personal Identification Number settings.
 *
 * @param [out] pinset: PIN settings information.
 *                      See @ref lte_getpin_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_pinset_sync(lte_getpin_t *pinset);

/**
 * Get Personal Identification Number settings.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting the PIN setting is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_pinset(get_pinset_cb_t callback);

/**
 * Set Personal Identification Number enable.
 *
 * @param [in] enable: "Enable" or "Disable".
 *                      Definition is as below.
 *  - @ref LTE_ENABLE
 *  - @ref LTE_DISABLE
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [out] attemptsleft: Number of attempts left.
 *                            Set only if failed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_pinenable_sync(bool enable, char *pincode,
                           uint8_t *attemptsleft);

/**
 * Set Personal Identification Number enable.
 *
 * @param [in] enable: "Enable" or "Disable".
 *                      Definition is as below.
 *  - @ref LTE_ENABLE
 *  - @ref LTE_DISABLE
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [in] callback: Callback function to notify that
 *                       setting of PIN enables/disables is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_pinenable(bool enable, char *pincode,
                      set_pinenable_cb_t callback);

/**
 * Change Personal Identification Number.
 *
 * It can be changed only when PIN is enable.
 *
 * @param [in] target_pin: Target of change PIN.
 *                      Definition is as below.
 *  - @ref LTE_TARGET_PIN
 *  - @ref LTE_TARGET_PIN2
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [in] new_pincode: New PIN code. Minimum number of digits is 4.
 *                          Maximum number of digits is 8, end with '\0'.
 *                          (i.e. Max 9 byte)
 *
 * @param [out] attemptsleft: Number of attempts left.
 *                            Set only if failed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_change_pin_sync(int8_t target_pin, char *pincode,
                        char *new_pincode, uint8_t *attemptsleft);

/**
 * Change Personal Identification Number.
 *
 * It can be changed only when PIN is enable.
 *
 * @param [in] target_pin: Target of change PIN.
 *                      Definition is as below.
 *  - @ref LTE_TARGET_PIN
 *  - @ref LTE_TARGET_PIN2
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [in] new_pincode: New PIN code. Minimum number of digits is 4.
 *                          Maximum number of digits is 8, end with '\0'.
 *                          (i.e. Max 9 byte)
 *
 * @param [in] callback: Callback function to notify that
 *                       change of PIN is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_change_pin(int8_t target_pin, char *pincode,
                   char *new_pincode, change_pin_cb_t callback);

/**
 * Enter Personal Identification Number.
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [in] new_pincode: Always set NULL.
 *                          This parameter is not currently used.
 *                          If this parameter has a value in it,
 *                          this API will error.
 *
 * @param [out] simstat: State after PIN enter.
 *                       As below value stored.
 * - @ref LTE_PINSTAT_READY
 * - @ref LTE_PINSTAT_SIM_PIN
 * - @ref LTE_PINSTAT_SIM_PUK
 * - @ref LTE_PINSTAT_PH_SIM_PIN
 * - @ref LTE_PINSTAT_PH_FSIM_PIN
 * - @ref LTE_PINSTAT_PH_FSIM_PUK
 * - @ref LTE_PINSTAT_SIM_PIN2
 * - @ref LTE_PINSTAT_SIM_PUK2
 * - @ref LTE_PINSTAT_PH_NET_PIN
 * - @ref LTE_PINSTAT_PH_NET_PUK
 * - @ref LTE_PINSTAT_PH_NETSUB_PIN
 * - @ref LTE_PINSTAT_PH_NETSUB_PUK
 * - @ref LTE_PINSTAT_PH_SP_PIN
 * - @ref LTE_PINSTAT_PH_SP_PUK
 * - @ref LTE_PINSTAT_PH_CORP_PIN
 * - @ref LTE_PINSTAT_PH_CORP_PUK
 *
 * @param [out] attemptsleft: Number of attempts left.
 *                            Set only if failed.
 *                            If simstat is other than PIN, PUK, PIN2, PUK2,
 *                            set the number of PIN.
 *
 * @note Running this API when the SIM state is
 *       other than LTE_PINSTAT_SIM_PIN will return an error.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 *
 * @deprecated This API will be removed in a future version
 */

int lte_enter_pin_sync(char *pincode, char *new_pincode,
                       uint8_t *simstat, uint8_t *attemptsleft);

/**
 * Enter Personal Identification Number.
 *
 * @param [in] pincode: Current PIN code. Minimum number of digits is 4.
 *                      Maximum number of digits is 8, end with '\0'.
 *                      (i.e. Max 9 byte)
 *
 * @param [in] new_pincode: Always set NULL.
 *                          This parameter is not currently used.
 *                          If this parameter has a value in it,
 *                          this API will error.
 *
 * @param [in] callback: Callback function to notify that
 *                       PIN enter is completed.
 *
 * @note Running this API when the SIM state is
 *       other than LTE_PINSTAT_SIM_PIN will return an error.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 *
 * @deprecated This API will be removed in a future version
 */

int lte_enter_pin(char *pincode, char *new_pincode,
                  enter_pin_cb_t callback);

/**
 * Get local time.
 *
 * @param [out] localtime: Local time. See @ref lte_localtime_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_localtime_sync(lte_localtime_t *localtime);

/**
 * Get local time.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting local time is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_localtime(get_localtime_cb_t callback);

/**
 * Get connected network operator information.
 *
 * @param [out] oper: A character string indicating network operator.
 *                    It is terminated with '\0' If it is not connected,
 *                    the first character is '\0'.
 *                    The maximum number of network operator areas
 *                    must be allocated. See @ref LTE_OPERATOR_LEN.
 * @param [in] len:   Length of the buffer for storing network operator.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
int lte_get_operator_sync(char *oper);
#else
int lte_get_operator_sync(char *oper, size_t len);
#endif

/**
 * Get connected network operator information.
 *
 * @param [in] callback: Callback function to notify when 
 *                       getting network operator information is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_operator(get_operator_cb_t callback);

/**
 * Get eDRX settings.
 *
 * @param [out] settings: eDRX settings. See @ref lte_edrx_setting_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_edrx_sync(lte_edrx_setting_t *settings);

/**
 * Get eDRX settings.
 *
 * @param [in] callback: Callback function to notify when 
 *                       getting eDRX settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_edrx(get_edrx_cb_t callback);

/**
 * Set eDRX settings.
 *
 * @param [in] settings: eDRX settings.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_edrx_sync(lte_edrx_setting_t *settings);

/**
 * Set eDRX settings.
 *
 * @param [in] settings: eDRX settings.
 *
 * @param [in] callback: Callback function to notify that 
 *                       eDRX settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_edrx(lte_edrx_setting_t *settings, set_edrx_cb_t callback);

/**
 * Get PSM settings.
 *
 * @param [out] settings: PSM settings. See @ref lte_psm_setting_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_psm_sync(lte_psm_setting_t *settings);

/**
 * Get PSM settings.
 *
 * @param [in] callback: Callback function to notify when 
 *                       getting PSM settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_psm(get_psm_cb_t callback);

/**
 * Set PSM settings.
 *
 * @param [in] settings: PSM settings.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_psm_sync(lte_psm_setting_t *settings);

/**
 * Set PSM settings.
 *
 * @param [in] settings: PSM settings.
 *
 * @param [in] callback: Callback function to notify that 
 *                       PSM settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_psm(lte_psm_setting_t *settings, set_psm_cb_t callback);

/**
 * Get CE settings.
 *
 * @param [out] settings: CE settings. See @ref lte_ce_setting_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_ce_sync(lte_ce_setting_t *settings);

/**
 * Get CE settings.
 *
 * @param [in] callback: Callback function to notify when 
 *                       getting CE settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_ce(get_ce_cb_t callback);

/**
 * Set CE settings.
 *
 * @param [in] settings: CE settings
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_ce_sync(lte_ce_setting_t *settings);

/**
 * Set CE settings.
 *
 * @param [in] settings: CE settings
 *
 * @param [in] callback: Callback function to notify that
 *                       CE settings are completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_ce(lte_ce_setting_t *settings, set_ce_cb_t callback);

/**
 * Notifies the SIM status to the application.
 *
 * The default report setting is disable.
 *
 * @param [in] simstat_callback: Callback function to notify that SIM state.
 *                               If NULL is set,
 *                               the report setting is disabled.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_simstat(simstat_report_cb_t simstat_callback);

/**
 * Notifies the Local time to the application.
 *
 * The default report setting is disable.
 *
 * @param [in] localtime_callback: Callback function to notify that
 *                                 local time. If NULL is set,
 *                                 the report setting is disabled.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_localtime(localtime_report_cb_t localtime_callback);

/**
 * Notifies the communication quality information to the application.
 *
 * Invoke the callback at the specified report interval.
 *
 * The default report setting is disable.
 *
 * @attention When changing the notification cycle, stop and start again.
 *
 * @param [in] quality_callback: Callback function to notify that
 *                               quality information. If NULL is set,
 *                               the report setting is disabled.
 *
 * @param [in] period: Reporting cycle in sec (1-4233600)
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_quality(quality_report_cb_t quality_callback,
                           uint32_t period);

/**
 * Notifies the LTE network cell information to the application.
 *
 * Invoke the callback at the specified report interval.
 *
 * The default report setting is disable.
 *
 * @attention When changing the notification cycle, stop and start again.
 *
 * @param [in] cellinfo_callback: Callback function to notify that
 *                                cell information. If NULL is set,
 *                                the report setting is disabled.
 *
 * @param [in] period: Reporting cycle in sec (1-4233600)
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_cellinfo(cellinfo_report_cb_t cellinfo_callback,
                            uint32_t period);

/**
 * Notifies the LTE network status to the application.
 *
 * The default report setting is disable.
 *
 * @param [in] netinfo_callback: Callback function to notify that
 *                               cell information. If NULL is set,
 *                               the report setting is disabled.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_report_netinfo(netinfo_report_cb_t netinfo_callback);

/**
 * Get LTE API last error information.
 *
 * Call this function when LTE_RESULT_ERROR is returned by
 * callback function. The detailed error information can be obtained.
 *
 * @param [in] info: Pointer of error information.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_errinfo(lte_errinfo_t *info);

/**
 * Get SIM information such as Mobile Country Code/Mobile Network Code.
 *
 * @param [in] option:   Indicates which parameter to get.
 *                       Bit setting definition is as below.
 *                       - @ref LTE_SIMINFO_GETOPT_MCCMNC
 *                       - @ref LTE_SIMINFO_GETOPT_SPN
 *                       - @ref LTE_SIMINFO_GETOPT_ICCID
 *                       - @ref LTE_SIMINFO_GETOPT_IMSI
 *                       - @ref LTE_SIMINFO_GETOPT_GID1
 *                       - @ref LTE_SIMINFO_GETOPT_GID2
 *
 * @param [out] siminfo: SIM information. See @ref lte_siminfo_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_siminfo_sync(uint32_t option, lte_siminfo_t *siminfo);

/**
 * Get SIM information such as Mobile Country Code/Mobile Network Code.
 *
 * @param [in] option:   Indicates which parameter to get.
 *                       Bit setting definition is as below.
 *                       - @ref LTE_SIMINFO_GETOPT_MCCMNC
 *                       - @ref LTE_SIMINFO_GETOPT_SPN
 *                       - @ref LTE_SIMINFO_GETOPT_ICCID
 *                       - @ref LTE_SIMINFO_GETOPT_IMSI
 *                       - @ref LTE_SIMINFO_GETOPT_GID1
 *                       - @ref LTE_SIMINFO_GETOPT_GID2
 *
 * @param [in] callback: Callback function to notify that
 *                       get of SIM information is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_siminfo(uint32_t option, get_siminfo_cb_t callback);

/**
 * Get eDRX dynamic parameter.
 *
 * @deprecated Use @ref lte_get_current_edrx instead.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * @param [in] callback: Callback function to notify when
 *                       getting eDRX dynamic parameter is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_dynamic_edrx_param(get_dynamic_edrx_param_cb_t callback);

/**
 * Get current eDRX settings.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * Get the settings negotiated between the modem and the network.
 *
 * @param [out] settings: Current eDRX settings.
 *                        See @ref lte_edrx_setting_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_current_edrx_sync(lte_edrx_setting_t *settings);

/**
 * Get current eDRX settings.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * Get the settings negotiated between the modem and the network.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting current eDRX settings is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_current_edrx(get_current_edrx_cb_t callback);

/**
 * Get PSM dynamic parameter.
 *
 * @deprecated Use @ref lte_get_current_psm instead.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * @param [in] callback: Callback function to notify when
 *                       getting PSM dynamic parameter is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_dynamic_psm_param(get_dynamic_psm_param_cb_t callback);

/**
 * Get current PSM settings.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * Get the settings negotiated between the modem and the network.
 *
 * @param [OUT] settings: Current PSM settings.
 *                        See @ref lte_psm_setting_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_current_psm_sync(lte_psm_setting_t *settings);

/**
 * Get current PSM settings.
 *
 * This API can be issued after connect to the LTE network
 * with lte_activate_pdn().
 *
 * Get the settings negotiated between the modem and the network.
 *
 * @param [in] callback: Callback function to notify when
 *                       getting current PSM settings is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_current_psm(get_current_psm_cb_t callback);

/**
 * Get communication quality information.
 *
 * @param [out] quality: Quality information. See @ref lte_quality_t
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_quality_sync(lte_quality_t *quality);

/**
 * Get communication quality information.
 *
 * @param [in] callback: Callback function to notify when 
 *                       getting quality information is completed.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_quality(get_quality_cb_t callback);

/**
 * Get LTE network cell information.
 *
 * @attention This function is not supported yet.
 *
 * @param [out] cellinfo: LTE network cell information.
 *                        See @ref lte_cellinfo_t
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_cellinfo_sync(lte_cellinfo_t *cellinfo);

/**
 * @brief Get RAT type
 *
 * @return On success, RAT type shown below is returned.
 *         - @ref LTE_RAT_CATM
 *         - @ref LTE_RAT_NBIOT
 * On failure, negative value is returned according to <errno.h>.
 */

int lte_get_rat_sync(void);

/**
 * @brief Set RAT setting
 *
 * @param [in] rat: RAT type. Definition is as below.
 *                  - @ref LTE_RAT_CATM
 *                  - @ref LTE_RAT_NBIOT
 * @param [in] persistent: Flag to keep RAT settings
 *                         after power off the modem.
 *                         Definition is as below.
 *                  - @ref LTE_ENABLE
 *                  - @ref LTE_DISABLE
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_set_rat_sync(uint8_t rat, bool persistent);

/**
 * @brief Get RAT information
 *
 * @param [out] info: Pointer to the structure that
 *                    stores RAT information
 *                    See @ref lte_ratinfo_t.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_get_ratinfo_sync(lte_ratinfo_t *info);

/**
 * Acquire the modem wakelock. If any wakelock is acquired, modem can't
 * enter to the sleep state.
 * Please call this API after calling lte_initialize().
 * Otherwise this API will result in an error.
 * Before calling lte_finalize(), must release all wakelocks
 * acquired by this API.
 *
 * @return On success, return the count of the current modem wakelock.
 * On failure, negative value is returned according to <errno.h>.
 */

int lte_acquire_wakelock(void);

/**
 * Release the modem wakelock. If all of the wakelock are released,
 * modem can enter to the sleep state.
 * Please call this API after calling lte_initialize().
 * Otherwise this API will result in an error.
 *
 * @return On success, return the count of the current modem wakelock.
 * On failure, negative value is returned according to <errno.h>.
 */

int lte_release_wakelock(void);

/**
 * @brief Send AT command to the modem.
 *
 * @param [in] cmd:         The AT command data.
 *                          Maximum length is LTE_AT_COMMAND_MAX_LEN.
 *                          AT command is shall begin with "AT" and end with '\r'.
 * @param [in] cmdlen:      Length of the AT command data.
 * @param [in] respbuff:    The area to store the AT command response.
 * @param [in] respbufflen: Length of the AT command response buffer.
 * @param [in] resplen:     The pointer to the area store
 *                          the length of AT command response.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_send_atcmd_sync(const char *cmd, int cmdlen,
  char *respbuff, int respbufflen, int *resplen);

/**
 * Run factory reset on the modem.
 *
 * @return On success, 0 is returned. On failure,
 * negative value is returned according to <errno.h>.
 */

int lte_factory_reset_sync(void);

/** @} */

/** @} */

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __APPS_INCLUDE_LTE_LTE_API_H */
