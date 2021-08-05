/****************************************************************************
 * apps/lte/lapi/src/lapi.c
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <nuttx/wireless/lte/lte_ioctl.h>

#include "lte/lte_api.h"
#include "lte/lte_fw_api.h"
#include "lte/lapi.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef ARRAY_SZ
#  define ARRAY_SZ(array) (sizeof(array)/sizeof(array[0]))
#endif

#define SETPIN_TARGETPIN_MIN LTE_TARGET_PIN
#define SETPIN_TARGETPIN_MAX LTE_TARGET_PIN2

#define APICMD_SETPINLOCK_PINCODE_LEN    9

#define SETPIN_MIN_PIN_LEN (4)
#define SETPIN_MAX_PIN_LEN ((APICMD_SETPINLOCK_PINCODE_LEN) - 1)

#define APICMD_ENTERPIN_PINCODE_LEN              9
#define ENTERPIN_MIN_PIN_LEN (4)
#define ENTERPIN_MAX_PIN_LEN ((APICMD_ENTERPIN_PINCODE_LEN) - 1)

#define CELLINFO_PERIOD_MIN (1)
#define CELLINFO_PERIOD_MAX (4233600)

#define QUALITY_PERIOD_MIN (1)
#define QUALITY_PERIOD_MAX (4233600)

#define ALTCOMBS_EDRX_CYCLE_WBS1_MIN      (LTE_EDRX_CYC_512)
#define ALTCOMBS_EDRX_CYCLE_WBS1_MAX      (LTE_EDRX_CYC_262144)
#define ALTCOMBS_EDRX_CYCLE_NBS1_MIN      (LTE_EDRX_CYC_2048)
#define ALTCOMBS_EDRX_CYCLE_NBS1_MAX      (LTE_EDRX_CYC_1048576)
#define ALTCOMBS_EDRX_PTW_WBS1_MIN        (LTE_EDRX_PTW_128)
#define ALTCOMBS_EDRX_PTW_WBS1_MAX        (LTE_EDRX_PTW_2048)
#define ALTCOMBS_EDRX_PTW_NBS1_MIN        (LTE_EDRX_PTW_256)
#define ALTCOMBS_EDRX_PTW_NBS1_MAX        (LTE_EDRX_PTW_4096)
#define ALTCOMBS_PSM_UNIT_T3324_MIN       (LTE_PSM_T3324_UNIT_2SEC)
#define ALTCOMBS_PSM_UNIT_T3324_MAX       (LTE_PSM_T3324_UNIT_6MIN)
#define ALTCOMBS_PSM_UNIT_T3412_MIN       (LTE_PSM_T3412_UNIT_2SEC)
#define ALTCOMBS_PSM_UNIT_T3412_MAX       (LTE_PSM_T3412_UNIT_320HOUR)
#define ALTCOMBS_EDRX_INVALID             (255)

#define APICMD_EDRX_ACTTYPE_NOTUSE   (0) /* eDRX is not running */
#define APICMD_EDRX_ACTTYPE_ECGSMIOT (1) /* EC-GSM-IoT (A/Gb mode) */
#define APICMD_EDRX_ACTTYPE_GSM      (2) /* GSM (A/Gb mode) */
#define APICMD_EDRX_ACTTYPE_IU       (3) /* UTRAN (Iu mode) */
#define APICMD_EDRX_ACTTYPE_WBS1     (4) /* E-UTRAN (WB-S1 mode) */
#define APICMD_EDRX_ACTTYPE_NBS1     (5) /* E-UTRAN (NB-S1 mode) */

#define ATCMD_HEADER     "AT"
#define ATCMD_HEADER_LEN (2)
#define ATCMD_FOOTER     '\r'
#define ATCMD_FOOTER_LEN (1)

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int lte_activate_pdn_inparam_check(lte_apn_setting_t *apn)
{
  int32_t mask = 0;

  if (!apn)
    {
      printf("apn is null.\n");
      return -EINVAL;
    }

  if ((!apn->apn) || (strnlen((char *)apn->apn, LTE_APN_LEN) >= LTE_APN_LEN))
    {
      printf("apn is length overflow.\n");
      return  -EINVAL;
    }

  if ((apn->ip_type < LTE_IPTYPE_V4) ||
      (apn->ip_type > LTE_IPTYPE_V4V6))
    {
      printf("ip type is invalid. iptype=%d\n", apn->ip_type);
      return -EINVAL;
    }

  if ((apn->auth_type < LTE_APN_AUTHTYPE_NONE) ||
      (apn->auth_type > LTE_APN_AUTHTYPE_CHAP))
    {
      printf("auth type is invalid. authtype=%d\n", apn->auth_type);
      return -EINVAL;
    }

  if (apn->user_name && apn->password)
    {
      if (strnlen((char *)apn->user_name, LTE_APN_USER_NAME_LEN) >=
        LTE_APN_USER_NAME_LEN)
        {
          printf("username is length overflow.\n");
          return -EINVAL;
        }

      if (strnlen((char *)apn->password, LTE_APN_PASSWD_LEN) >=
        LTE_APN_PASSWD_LEN)
        {
          printf("password is length overflow.\n");
          return  -EINVAL;
        }
    }
  else
    {
      if (apn->auth_type != LTE_APN_AUTHTYPE_NONE)
        {
          printf("authentication information is invalid.\n");
          return -EINVAL;
        }
    }

  mask = (LTE_APN_TYPE_DEFAULT |
    LTE_APN_TYPE_MMS | LTE_APN_TYPE_SUPL | LTE_APN_TYPE_DUN |
    LTE_APN_TYPE_HIPRI | LTE_APN_TYPE_FOTA | LTE_APN_TYPE_IMS |
    LTE_APN_TYPE_CBS | LTE_APN_TYPE_IA | LTE_APN_TYPE_EMERGENCY);
  if (0 == (apn->apn_type & mask))
    {
      printf("apn type is invalid. apntype=%08ld / mask=%08ld \n",
        apn->apn_type, mask);
      return -EINVAL;
    }

  return OK;
}

static int lte_change_pin_inparam_check(int8_t target_pin, int8_t *pincode,
  int8_t *new_pincode)
{
  uint8_t pinlen = 0;

  if (!pincode || !new_pincode)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  if (SETPIN_TARGETPIN_MIN > target_pin || SETPIN_TARGETPIN_MAX < target_pin)
    {
      printf("Unsupport change type. type:%d\n", target_pin);
      return -EINVAL;
    }

  pinlen = strnlen((FAR char *)pincode, SETPIN_MAX_PIN_LEN);
  if (pinlen < SETPIN_MIN_PIN_LEN || SETPIN_MAX_PIN_LEN < pinlen)
    {
      return -EINVAL;
    }

  pinlen = strnlen((FAR char *)new_pincode, SETPIN_MAX_PIN_LEN);
  if (pinlen < SETPIN_MIN_PIN_LEN || SETPIN_MAX_PIN_LEN < pinlen)
    {
      return -EINVAL;
    }

  return OK;
}

static int lte_deactivate_pdn_inparam_check(uint8_t session_id)
{
  if (LTE_SESSION_ID_MIN > session_id ||
      LTE_SESSION_ID_MAX < session_id)
    {
      printf("Invalid session id %d.\n", session_id);
      return -EINVAL;
    }

  return OK;
}

static int lte_enter_pin_inparam_check(int8_t *pincode, int8_t *new_pincode)
{
  uint8_t pinlen = 0;

  if (!pincode)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  pinlen = strnlen((FAR char *)pincode, ENTERPIN_MAX_PIN_LEN);
  if (pinlen < ENTERPIN_MIN_PIN_LEN || ENTERPIN_MAX_PIN_LEN < pinlen)
    {
      printf("Invalid PIN code length.length:%d\n", pinlen);
      return -EINVAL;
    }

  if (new_pincode)
    {
      printf("lte_enter_pin() doesn't support entering PUK code.\n");
      printf("lte_enter_pin_sync() doesn't support entering PUK code.\n");
      return -EINVAL;
    }

  return OK;
}

static int lte_get_netinfo_inparam_check(uint8_t pdn_num)
{
  if (LTE_SESSION_ID_MIN > pdn_num || LTE_SESSION_ID_MAX < pdn_num)
    {
      return -EINVAL;
    }

  return OK;
}

static int lte_get_siminfo_inparam_check(uint32_t option)
{
  uint32_t mask = 0;

  mask = (LTE_SIMINFO_GETOPT_MCCMNC |
          LTE_SIMINFO_GETOPT_SPN |
          LTE_SIMINFO_GETOPT_ICCID |
          LTE_SIMINFO_GETOPT_IMSI |
          LTE_SIMINFO_GETOPT_GID1 |
          LTE_SIMINFO_GETOPT_GID2);

  if (0 == (option & mask))
    {
      return -EINVAL;
    }

  return OK;
}

static int lte_set_ce_inparam_check(lte_ce_setting_t *settings)
{
  if (!settings)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  if (settings->mode_a_enable == LTE_ENABLE ||
      settings->mode_a_enable == LTE_DISABLE)
    {
      printf("mode_a_enable is invalid. mode_a_enable=%d\n",
        settings->mode_a_enable);
      return -EINVAL;
    }

  if (settings->mode_b_enable == LTE_ENABLE ||
      settings->mode_b_enable == LTE_DISABLE)
    {
      printf("mode_b_enable is invalid. mode_b_enable=%d\n",
        settings->mode_b_enable);
      return -EINVAL;
    }

  return OK;
}

static int lte_set_edrx_inparam_check(lte_edrx_setting_t *settings)
{
  int32_t ret = 0;

  if (!settings)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  if (settings->act_type != LTE_EDRX_ACTTYPE_WBS1 &&
      settings->act_type != LTE_EDRX_ACTTYPE_NBS1 &&
      settings->act_type != LTE_EDRX_ACTTYPE_ECGSMIOT &&
      settings->act_type != LTE_EDRX_ACTTYPE_GSM &&
      settings->act_type != LTE_EDRX_ACTTYPE_IU &&
      settings->act_type != LTE_EDRX_ACTTYPE_NOTUSE)
    {
      printf("Input argument act_type is invalid.\n");
      return -EINVAL;
    }

  ret = lte_get_rat_sync();
  if (ret < 0 && ret != -ENOTSUP)
    {
      printf("Unable to read RAT setting from the device. ret: [%ld].\n",
        ret);
      return ret;
    }
  else if (ret == -ENOTSUP)
    {
      /* act_type check for protocol version V1 */

      if (LTE_EDRX_ACTTYPE_NOTUSE != settings->act_type &&
          LTE_EDRX_ACTTYPE_WBS1   != settings->act_type)
        {
          printf("Operation is not allowed[act_type : %d].\n",
            settings->act_type);
          return -EPERM;
        }
    }
  else
    {
      /* act_type check for version V4 or later */

      if (!((ret == LTE_RAT_CATM
             && settings->act_type == LTE_EDRX_ACTTYPE_WBS1) ||
            (ret == LTE_RAT_NBIOT
             && settings->act_type == LTE_EDRX_ACTTYPE_NBS1) ||
            (settings->act_type == LTE_EDRX_ACTTYPE_NOTUSE)))
        {
          printf("Operation is not allowed[act_type : %d, RAT : %ld].\n",
            settings->act_type, ret);
          return -EPERM;
        }
    }

  if (settings->enable)
    {
      if (settings->act_type == LTE_EDRX_ACTTYPE_WBS1)
        {
          if (!(ALTCOMBS_EDRX_CYCLE_WBS1_MIN <= settings->edrx_cycle &&
            settings->edrx_cycle <= ALTCOMBS_EDRX_CYCLE_WBS1_MAX))
            {
              printf("Input argument edrx_cycle is invalid.\n");
              return -EINVAL;
            }

          if (!(ALTCOMBS_EDRX_PTW_WBS1_MIN <= settings->ptw_val &&
            settings->ptw_val <= ALTCOMBS_EDRX_PTW_WBS1_MAX))
            {
              printf("Input argument ptw is invalid.\n");
              return -EINVAL;
            }
        }

      if (settings->act_type == LTE_EDRX_ACTTYPE_NBS1)
        {
          if (!(ALTCOMBS_EDRX_CYCLE_NBS1_MIN <= settings->edrx_cycle &&
              settings->edrx_cycle <= ALTCOMBS_EDRX_CYCLE_NBS1_MAX))
            {
              printf("Input argument edrx_cycle is invalid.\n");
              return -EINVAL;
            }

          if (!(ALTCOMBS_EDRX_PTW_NBS1_MIN <= settings->ptw_val &&
              settings->ptw_val <= ALTCOMBS_EDRX_PTW_NBS1_MAX))
            {
              printf("Input argument ptw is invalid.\n");
              return -EINVAL;
            }
        }
    }

  return OK;
}

static int lte_set_pinenable_inparam_check(bool enable, int8_t *pincode)
{
  uint8_t pinlen = 0;

  if (!pincode)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  pinlen = strnlen((FAR char *)pincode, SETPIN_MAX_PIN_LEN);
  if (pinlen < SETPIN_MIN_PIN_LEN || SETPIN_MAX_PIN_LEN < pinlen)
    {
      return -EINVAL;
    }

  return OK;
}

static int lte_set_psm_inparam_check(lte_psm_setting_t *settings)
{
  if (!settings)
    {
      printf("Input argument is NULL.\n");
      return -EINVAL;
    }

  if (LTE_ENABLE == settings->enable)
    {
      if (settings->req_active_time.unit < LTE_PSM_T3324_UNIT_2SEC ||
          settings->req_active_time.unit > LTE_PSM_T3324_UNIT_DEACT)
        {
          printf("Invalid rat_time unit :%d\n",
            settings->req_active_time.unit);
          return -EINVAL;
        }

      if (settings->req_active_time.time_val < LTE_PSM_TIMEVAL_MIN ||
          settings->req_active_time.time_val > LTE_PSM_TIMEVAL_MAX)
        {
          printf("Invalid rat_time time_val :%d\n",
            settings->req_active_time.time_val);
          return -EINVAL;
        }

      if (settings->ext_periodic_tau_time.unit < LTE_PSM_T3412_UNIT_2SEC ||
          settings->ext_periodic_tau_time.unit > LTE_PSM_T3412_UNIT_DEACT)
        {
          printf("Invalid tau_time unit :%d\n",
            settings->ext_periodic_tau_time.unit);
          return -EINVAL;
        }

      if (settings->ext_periodic_tau_time.time_val < LTE_PSM_TIMEVAL_MIN ||
          settings->ext_periodic_tau_time.time_val > LTE_PSM_TIMEVAL_MAX)
        {
          printf("Invalid tau_time time_val :%d\n",
            settings->ext_periodic_tau_time.time_val);
          return -EINVAL;
        }
    }

  return OK;
}

static int lte_set_rat_inparam_check(uint8_t rat, bool persistent)
{
  if (rat != LTE_RAT_CATM &&
      rat != LTE_RAT_NBIOT)
    {
      printf("RAT type is invalid [%d].\n", rat);
      return -EINVAL;
    }

  if (persistent != LTE_ENABLE &&
      persistent != LTE_DISABLE)
    {
      printf("persistent is invalid [%d].\n", persistent);
      return -EINVAL;
    }

  return OK;
}

static int lte_set_report_cellinfo_inparam_check(
  cellinfo_report_cb_t callback, uint32_t period)
{
  if (callback)
    {
      if (CELLINFO_PERIOD_MIN > period || CELLINFO_PERIOD_MAX < period)
        {
          printf("Invalid parameter.\n");
          return -EINVAL;
        }
    }

  return OK;
}

static int lte_set_report_quality_inparam_check(quality_report_cb_t callback,
  uint32_t period)
{
  if (callback)
    {
      if (QUALITY_PERIOD_MIN > period || QUALITY_PERIOD_MAX < period)
        {
          printf("Invalid parameter.\n");
          return -EINVAL;
        }
    }

  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int32_t lte_radio_on_sync(void)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_RADIOON,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_radio_off_sync(void)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_RADIOOFF,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_activate_pdn_sync(lte_apn_setting_t *apn, lte_pdn_t *pdn)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      apn
    };

  FAR void *outarg[] =
    {
      &result, pdn
    };

  if (lte_activate_pdn_inparam_check(apn) || pdn == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_ACTPDN,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_deactivate_pdn_sync(uint8_t session_id)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &session_id
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_deactivate_pdn_inparam_check(session_id))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_DEACTPDN,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_netinfo_sync(uint8_t pdn_num, lte_netinfo_t *info)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &pdn_num
    };

  FAR void *outarg[] =
    {
      &result, info, &pdn_num
    };

  if (lte_get_netinfo_inparam_check(pdn_num) || info == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETNETINFO,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_imscap_sync(bool *imscap)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, imscap
    };

  if (imscap == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_IMSCAP,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_version_sync(lte_version_t *version)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, version
    };

  if (version == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETVER,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_phoneno_sync(int8_t *phoneno)
{
  int32_t ret;
  int32_t result;
  uint8_t errcause;
  FAR void *outarg[] =
    {
      &result, &errcause, phoneno
    };

  if (phoneno == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETPHONE,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_imsi_sync(int8_t *imsi)
{
  int32_t ret;
  int32_t result;
  uint8_t errcause;
  FAR void *outarg[] =
    {
      &result, &errcause, imsi
    };

  if (imsi == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETIMSI,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_imei_sync(int8_t *imei)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, imei
    };

  if (imei == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETIMEI,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_pinset_sync(lte_getpin_t *pinset)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, pinset
    };

  if (pinset == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETPINSET,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_pinenable_sync(bool enable, int8_t *pincode,
  uint8_t *attemptsleft)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &enable, pincode
    };

  FAR void *outarg[] =
    {
      &result, attemptsleft
    };

  if (lte_set_pinenable_inparam_check(enable, pincode) ||
    attemptsleft == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_PINENABLE,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_change_pin_sync(int8_t target_pin, int8_t *pincode,
  int8_t *new_pincode, uint8_t *attemptsleft)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &target_pin, pincode, new_pincode
    };

  FAR void *outarg[] =
    {
      &result, attemptsleft
    };

  if (lte_change_pin_inparam_check(target_pin, pincode, new_pincode) ||
    attemptsleft == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_CHANGEPIN,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_enter_pin_sync(int8_t *pincode, int8_t *new_pincode,
  uint8_t *simstat, uint8_t *attemptsleft)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      pincode, new_pincode
    };

  FAR void *outarg[] =
    {
      &result, simstat, attemptsleft
    };

  lte_getpin_t pinset =
    {
      0
    };

  if (lte_enter_pin_inparam_check(pincode, new_pincode) || simstat == NULL ||
    attemptsleft == NULL)
    {
      return -EINVAL;
    }

  ret = lte_get_pinset_sync(&pinset);
  if (ret < 0)
    {
      printf("Failed to get pinset.%ld\n", ret);
      return ret;
    }

  if (simstat)
    {
      *simstat = pinset.status;
    }

  if (attemptsleft)
    {
      if (pinset.status == LTE_PINSTAT_SIM_PUK)
        {
          *attemptsleft = pinset.puk_attemptsleft;
        }
      else
        {
          *attemptsleft = pinset.pin_attemptsleft;
        }
    }

  if (pinset.enable == LTE_DISABLE)
    {
      printf(
        "PIN lock is disable. Don't need to run lte_enter_pin_sync().\n");
      return -EPERM;
    }
  else if (pinset.status != LTE_PINSTAT_SIM_PIN)
    {
      if (pinset.status == LTE_PINSTAT_SIM_PUK)
        {
          printf(
            "This SIM is PUK locked. lte_enter_pin_sync() can't be used.\n");
        }
      else
        {
          printf("PIN is already unlocked. "
            "Don't need to run lte_enter_pin_sync(). status:%d\n",
            pinset.status);
        }

      return -EPERM;
    }

  ret = lapi_req(LTE_CMDID_ENTERPIN,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_localtime_sync(lte_localtime_t *localtime)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, localtime
    };

  if (localtime == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETLTIME,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_operator_sync(int8_t *oper)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, oper
    };

  if (oper == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETOPER,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_edrx_sync(lte_edrx_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  bool    is_edrxevt;
  FAR void *outarg[] =
    {
      &result, settings, &is_edrxevt
    };

  if (settings == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETEDRX,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_edrx_sync(lte_edrx_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      settings
    };

  FAR void *outarg[] =
    {
      &result
    };

  ret = lte_set_edrx_inparam_check(settings);
  if (ret < 0)
    {
      return ret;
    }

  ret = lapi_req(LTE_CMDID_SETEDRX,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_psm_sync(lte_psm_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  int32_t id = LTE_CMDID_GETPSM;
  bool    is_psmevt;
  FAR void *inarg[] =
    {
      &id
    };

  FAR void *outarg[] =
    {
      &result, settings, &is_psmevt
    };

  if (settings == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETPSM,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_psm_sync(lte_psm_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      settings
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_set_psm_inparam_check(settings))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_SETPSM,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_ce_sync(lte_ce_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, settings
    };

  if (settings == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETCE,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_ce_sync(lte_ce_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      settings
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_set_ce_inparam_check(settings))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_SETCE,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_siminfo_sync(uint32_t option, lte_siminfo_t *siminfo)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &option
    };

  FAR void *outarg[] =
    {
      &result, siminfo
    };

  if (lte_get_siminfo_inparam_check(option) || siminfo == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETSIMINFO,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_current_edrx_sync(lte_edrx_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  bool    is_getcedrxevt;
  FAR void *outarg[] =
    {
      &result, settings, &is_getcedrxevt
    };

  if (settings == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETCEDRX,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_current_psm_sync(lte_psm_setting_t *settings)
{
  int32_t ret;
  int32_t result;
  bool    is_getcpsmevt;
  FAR void *outarg[] =
    {
      &result, settings, &is_getcpsmevt
    };

  if (settings == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETCPSM,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_quality_sync(lte_quality_t *quality)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, quality
    };

  if (quality == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETQUAL,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_cellinfo_sync(lte_cellinfo_t *cellinfo)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, cellinfo
    };

  if (cellinfo == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETCELL,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_rat_sync(void)
{
  int32_t ret;
  int32_t result;
  lte_ratinfo_t ratinfo;
  FAR void *outarg[] =
    {
      &result, &ratinfo
    };

  ret = lapi_req(LTE_CMDID_GETRAT,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = ratinfo.rat;
    }

  return ret;
}

int32_t lte_set_rat_sync(uint8_t rat, bool persistent)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      &rat, &persistent
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_set_rat_inparam_check(rat, persistent))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_SETRAT,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_ratinfo_sync(lte_ratinfo_t *info)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result, info
    };

  if (info == NULL)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETRATINFO,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_data_allow_sync(uint8_t session_id, uint8_t allow,
                            uint8_t roaming_allow)
{
  printf("lte_data_allow_sync() is not supported.\n");

  return -EOPNOTSUPP;
}

int32_t lte_activate_pdn_cancel(void)
{
  int32_t ret;
  int32_t result;
  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_ACTPDNCAN,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_radio_on(radio_on_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_RADIOON | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_radio_off(radio_off_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_RADIOOFF | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_activate_pdn(lte_apn_setting_t *apn, activate_pdn_cb_t callback)
{
  FAR void *inarg[] =
    {
      apn
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_activate_pdn_inparam_check(apn))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_ACTPDN | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_deactivate_pdn(uint8_t session_id, deactivate_pdn_cb_t callback)
{
  FAR void *inarg[] =
    {
      &session_id
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_deactivate_pdn_inparam_check(session_id))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_DEACTPDN | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_netinfo(get_netinfo_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETNETINFO | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_imscap(get_imscap_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_IMSCAP | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_version(get_ver_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETVER | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_phoneno(get_phoneno_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETPHONE | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_imsi(get_imsi_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETIMSI | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_imei(get_imei_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETIMEI | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_pinset(get_pinset_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETPINSET | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_set_pinenable(bool enable, int8_t *pincode,
  set_pinenable_cb_t callback)
{
  FAR void *inarg[] =
    {
      &enable, pincode
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_set_pinenable_inparam_check(enable, pincode))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_PINENABLE | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_change_pin(int8_t target_pin, int8_t *pincode,
  int8_t *new_pincode, change_pin_cb_t callback)
{
  FAR void *inarg[] =
    {
      &target_pin, pincode, new_pincode
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_change_pin_inparam_check(target_pin, pincode, new_pincode))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_CHANGEPIN | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_enter_pin(int8_t *pincode, int8_t *new_pincode,
  enter_pin_cb_t callback)
{
  FAR void *inarg[] =
    {
      pincode, new_pincode
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_enter_pin_inparam_check(pincode, new_pincode))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_ENTERPIN | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_localtime(get_localtime_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETLTIME | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_operator(get_operator_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETOPER | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_edrx(get_edrx_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETEDRX | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_set_edrx(lte_edrx_setting_t *settings, set_edrx_cb_t callback)
{
  int32_t ret;
  FAR void *inarg[] =
    {
      settings
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  ret = lte_set_edrx_inparam_check(settings);
  if (ret < 0)
    {
      return ret;
    }

  return lapi_req(LTE_CMDID_SETEDRX | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_psm(get_psm_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETPSM | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_set_psm(lte_psm_setting_t *settings, set_psm_cb_t callback)
{
  FAR void *inarg[] =
    {
      settings
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_set_psm_inparam_check(settings))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_SETPSM | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_ce(get_ce_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETCE | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_set_ce(lte_ce_setting_t *settings, set_ce_cb_t callback)
{
  FAR void *inarg[] =
    {
      settings
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_set_ce_inparam_check(settings))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_SETCE | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_siminfo(uint32_t option, get_siminfo_cb_t callback)
{
  FAR void *inarg[] =
    {
      &option
    };

  if (callback == NULL)
    {
      return -EINVAL;
    }

  if (lte_get_siminfo_inparam_check(option))
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETSIMINFO | LTE_CMDOPT_ASYNC_BIT,
                  (FAR void *)inarg, ARRAY_SZ(inarg),
                  NULL, 0, callback);
}

int32_t lte_get_current_edrx(get_current_edrx_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETCEDRX | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_dynamic_edrx_param(get_dynamic_edrx_param_cb_t callback)
{
  return lte_get_current_edrx(callback);
}

int32_t lte_get_current_psm(get_current_psm_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETCPSM | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_get_dynamic_psm_param(get_dynamic_psm_param_cb_t callback)
{
  return lte_get_current_psm(callback);
}

int32_t lte_get_quality(get_quality_cb_t callback)
{
  if (callback == NULL)
    {
      return -EINVAL;
    }

  return lapi_req(LTE_CMDID_GETQUAL | LTE_CMDOPT_ASYNC_BIT,
                  NULL, 0, NULL, 0, callback);
}

int32_t lte_data_allow(uint8_t session_id, uint8_t allow,
                       uint8_t roaming_allow, data_allow_cb_t callback)
{
  printf("lte_data_allow() is not supported.\n");

  return -EOPNOTSUPP;
}

int32_t lte_set_report_netinfo(netinfo_report_cb_t callback)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      callback
    };

  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_REPNETINFO,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 callback);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_report_simstat(simstat_report_cb_t callback)
{
  int32_t ret;
  int32_t result;
  int32_t id = LTE_CMDID_REPSIMSTAT;
  FAR void *inarg[] =
    {
      callback, &id
    };

  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_REPSIMSTAT,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 callback);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_report_localtime(localtime_report_cb_t callback)
{
  int32_t ret;
  int32_t result;
  int32_t id = LTE_CMDID_REPLTIME;
  FAR void *inarg[] =
    {
      callback, &id
    };

  FAR void *outarg[] =
    {
      &result
    };

  ret = lapi_req(LTE_CMDID_REPLTIME,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 callback);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_report_quality(quality_report_cb_t callback, uint32_t period)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      callback, &period
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_set_report_quality_inparam_check(callback, period))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_REPQUAL,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 callback);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_set_report_cellinfo(cellinfo_report_cb_t callback,
  uint32_t period)
{
  int32_t ret;
  int32_t result;
  FAR void *inarg[] =
    {
      callback, &period
    };

  FAR void *outarg[] =
    {
      &result
    };

  if (lte_set_report_cellinfo_inparam_check(callback, period))
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_REPCELL,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 callback);
  if (ret == 0)
    {
      ret = result;
    }

  return ret;
}

int32_t lte_get_errinfo(lte_errinfo_t *info)
{
  int32_t ret;

  FAR void *outarg[] =
    {
      info
    };

  if (!info)
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_GETERRINFO,
                 NULL, 0,
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);

  return ret;
}

int32_t ltefw_inject_deltaimage(const struct ltefw_injectdata_s *inject_data,
  uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_get_deltaimage_len(void)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_exec_deltaupdate(uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int32_t ltefw_get_deltaupdate_result(uint16_t *ltefw_result)
{
  /* TODO: implement */

  return -EOPNOTSUPP;
}

int lte_send_atcmd_sync(const char *cmd, int cmdlen,
  char *respbuff, int respbufflen, int *resplen)
{
  int32_t ret;
  FAR void *inarg[] =
    {
      (FAR void *)cmd, &cmdlen
    };

  FAR void *outarg[] =
    {
      respbuff, &respbufflen, resplen
    };

  if (!cmd
    || (ATCMD_HEADER_LEN + ATCMD_FOOTER_LEN) > cmdlen
    || LTE_AT_COMMAND_MAX_LEN < cmdlen
    || !respbuff || !respbufflen || !resplen)
    {
      return -EINVAL;
    }

  if (0 != strncmp(cmd, ATCMD_HEADER, ATCMD_HEADER_LEN))
    {
      return -EINVAL;
    }

  if (ATCMD_FOOTER != cmd[cmdlen - ATCMD_FOOTER_LEN])
    {
      return -EINVAL;
    }

  ret = lapi_req(LTE_CMDID_SENDATCMD,
                 (FAR void *)inarg, ARRAY_SZ(inarg),
                 (FAR void *)outarg, ARRAY_SZ(outarg),
                 NULL);

  return ret;
}
