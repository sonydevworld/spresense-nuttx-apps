/****************************************************************************
 * apps/lte/alt1250/alt1250_evt.c
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
#include <semaphore.h>
#include <nuttx/modem/alt1250.h>
#include <nuttx/wireless/lte/lte_ioctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include <nuttx/net/dns.h>

#include "alt1250_dbg.h"
#include "lte/lapi.h"
#include "lte/lte_api.h"

#include "alt1250_evt.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef ARRAY_SZ
#  define ARRAY_SZ(array) (sizeof(array)/sizeof(array[0]))
#endif

#define TABLE_CONTENT(cid, acid, outp) \
  { .cmdid = LTE_CMDID_##cid, .altcid = APICMDID_##acid, \
    .outparam = outp, .outparamlen = ARRAY_SZ(outp) }

#define NCBTABLES (8 + ALTCOM_NSOCKET) /* 8 is the maximum number of events */

#define IS_REPORT_API(cmdid) \
  ( LTE_ISCMDGRP_EVENT(cmdid) || cmdid == LTE_CMDID_SETRESTART )

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static uint64_t lte_set_report_restart_exec_cb(FAR void *cb,
  FAR void **cbarg);
static uint64_t lte_radio_on_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_radio_off_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_activate_pdn_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_deactivate_pdn_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_netinfo_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_imscap_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_version_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_phoneno_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_imsi_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_imei_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_pinset_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_pinenable_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_change_pin_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_enter_pin_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_localtime_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_operator_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_edrx_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_edrx_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_psm_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_psm_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_ce_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_ce_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_siminfo_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_current_edrx_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_current_psm_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_get_quality_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_report_netinfo_exec_cb(FAR void *cb,
  FAR void **cbarg);
static uint64_t lte_set_report_simstat_exec_cb(FAR void *cb,
  FAR void **cbarg);
static uint64_t lte_set_report_localtime_exec_cb(FAR void *cb,
  FAR void **cbarg);
static uint64_t lte_set_reportevt_exec_cb(FAR void *cb, FAR void **cbarg);
static uint64_t lte_set_report_quality_exec_cb(FAR void *cb,
  FAR void **cbarg);
static uint64_t lte_set_report_cellinfo_exec_cb(FAR void *cb,
  FAR void **cbarg);

static void *get_cbfunc(uint32_t cmdid);
static uint64_t alt1250_evt_search(uint32_t cmdid);

/****************************************************************************
 * Private Data Types
 ****************************************************************************/

struct cbinfo_s
{
  uint32_t cmdid;
  uint64_t (*cb)(FAR void *cb, FAR void **cbarg);
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* event argument for LTE_CMDID_SETRESTART */

static uint32_t g_reason;
static void *g_setrestartargs[] =
{
  &g_reason
};

/* event argument for LTE_CMDID_GETVER */

static int g_getverret;
static lte_version_t g_ver;
static void *g_getverargs[] =
{
  &g_getverret, &g_ver
};

/* event argument for LTE_CMDID_RADIOON */

static int g_radioonret;
static void *g_radioonargs[] =
{
  &g_radioonret
};

/* event argument for LTE_CMDID_RADIOOFF */

static int g_radiooffret;
static void *g_radiooffargs[] =
{
  &g_radiooffret
};

/* event argument for LTE_CMDID_ACTPDN */

static int g_actpdnret;
static lte_pdn_t g_pdn;
static void *g_actpdnargs[] =
{
  &g_actpdnret, &g_pdn
};

/* event argument for LTE_CMDID_DEACTPDN */

static int g_deactpdnret;
static void *g_deactpdnargs[] =
{
  &g_deactpdnret
};

/* event argument for LTE_CMDID_GETNETINFO */

static int g_getnetinforet;
static lte_pdn_t g_pdninfo[LTE_SESSION_ID_MAX];
static lte_netinfo_t g_netinfo =
{
  .pdn_stat = g_pdninfo
};

static uint8_t g_pdn_num = LTE_SESSION_ID_MAX;
static void *g_netinfoargs[] =
{
  &g_getnetinforet, &g_netinfo, &g_pdn_num
};

/* event argument for LTE_CMDID_IMSCAP */

static int g_imscapret;
static bool g_imscap;
static void *g_imscapargs[] =
{
  &g_imscapret, &g_imscap
};

/* event argument for LTE_CMDID_GETPHONE */

static int g_getphoneret;
static uint8_t g_getphoneerrcause;
static char g_phoneno[LTE_PHONENO_LEN];
#ifndef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
static size_t g_phonenolen = LTE_PHONENO_LEN;
#endif
static void *g_getphoneargs[] =
{
#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
  &g_getphoneret, &g_getphoneerrcause, g_phoneno
#else
  &g_getphoneret, &g_getphoneerrcause, g_phoneno, &g_phonenolen
#endif
};

/* event argument for LTE_CMDID_GETIMSI */

static int g_getimsiret;
static uint8_t g_getimsierrcause;
static char g_imsi[LTE_SIMINFO_IMSI_LEN];
#ifndef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
static size_t g_imsilen = LTE_SIMINFO_IMSI_LEN;
#endif
static void *g_getimsiargs[] =
{
#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
  &g_getimsiret, &g_getimsierrcause, g_imsi
#else
  &g_getimsiret, &g_getimsierrcause, g_imsi, &g_imsilen
#endif
};

/* event argument for LTE_CMDID_GETIMEI */

static int g_getimeiret;
static char g_imei[LTE_IMEI_LEN];
#ifndef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
static size_t g_imeilen = LTE_IMEI_LEN;
#endif
static void *g_getimeiargs[] =
{
#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
  &g_getimeiret, g_imei
#else
  &g_getimeiret, g_imei, &g_imeilen
#endif
};

/* event argument for LTE_CMDID_GETPINSET */

static int g_getpinsetret;
static lte_getpin_t g_pinset;
static void *g_getpinsetargs[] =
{
  &g_getpinsetret, &g_pinset
};

/* event argument for LTE_CMDID_PINENABLE */

static int g_pinenableret;
static uint8_t g_pineattleft;
static void *g_pinenableargs[] =
{
  &g_pinenableret, &g_pineattleft
};

/* event argument for LTE_CMDID_CHANGEPIN */

static int g_changepinret;
static uint8_t g_chanattleft;
static void *g_changepinargs[] =
{
  &g_changepinret, &g_chanattleft
};

/* event argument for LTE_CMDID_ENTERPIN */

static int g_enterpinret;
static uint8_t g_entpinsimstat;
static uint8_t g_entpinattleft;
static void *g_enterpinargs[] =
{
  &g_enterpinret, &g_entpinsimstat, &g_entpinattleft
};

/* event argument for LTE_CMDID_GETLTIME */

static int g_getltimeret;
static lte_localtime_t g_ltime;
static void *g_getltimeargs[] =
{
  &g_getltimeret, &g_ltime
};

/* event argument for LTE_CMDID_GETOPER */

static int g_getoperret;
static char g_oper[LTE_OPERATOR_LEN];
#ifndef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
static size_t g_operlen = LTE_OPERATOR_LEN;
#endif
static void *g_getoperargs[] =
{
#ifdef CONFIG_LTE_LAPI_KEEP_COMPATIBILITY
  &g_getoperret, g_oper
#else
  &g_getoperret, g_oper, &g_operlen
#endif
};

/* event argument for LTE_CMDID_GETEDRX */

static int g_getedrxret;
static lte_edrx_setting_t g_getedrx;
static bool g_is_getedrxevt;
static void *g_getedrxargs[] =
{
  &g_getedrxret, &g_getedrx, &g_is_getedrxevt
};

/* event argument for LTE_CMDID_SETEDRX */

static int g_setedrxret;
static void *g_setedrxargs[] =
{
  &g_setedrxret
};

/* event argument for LTE_CMDID_GETPSM */

static int g_getpsmret;
static lte_psm_setting_t g_getpsm;
static bool g_is_getpsmevt;
static void *g_getpsmargs[] =
{
  &g_getpsmret, &g_getpsm, &g_is_getpsmevt
};

/* event argument for LTE_CMDID_SETPSM */

static int g_setpsmret;
static void *g_setpsmargs[] =
{
  &g_setpsmret
};

/* event argument for LTE_CMDID_GETCE */

static int g_getceret;
static lte_ce_setting_t g_getce;
static void *g_getceargs[] =
{
  &g_getceret, &g_getce
};

/* event argument for LTE_CMDID_SETCE */

static int g_setceret;
static void *g_setceargs[] =
{
  &g_setceret
};

/* event argument for LTE_CMDID_GETSIMINFO */

static int g_setsiminforet;
static lte_siminfo_t g_siminfo;
static void *g_getsiminfoargs[] =
{
  &g_setsiminforet, &g_siminfo
};

/* event argument for LTE_CMDID_GETCEDRX */

static int g_getcedrxret;
static lte_edrx_setting_t g_getcedrx;
static bool g_is_getcedrxevt;
static void *g_getcedrxargs[] =
{
  &g_getcedrxret, &g_getcedrx, &g_is_getcedrxevt
};

/* event argument for LTE_CMDID_GETCPSM */

static int g_getcpsmret;
static lte_psm_setting_t g_getcpsm;
static bool g_is_getcpsmevt;
static void *g_getcpsmargs[] =
{
  &g_getcpsmret, &g_getcpsm, &g_is_getcpsmevt
};

/* event argument for LTE_CMDID_GETQUAL */

static int g_getqualret;
static lte_quality_t g_getqual;
static void *g_getqualargs[] =
{
  &g_getqualret, &g_getqual
};

/* event argument for LTE_CMDID_GETCELL */

static int g_getcellret;
static lte_neighbor_cell_t g_neighbors[LTE_NEIGHBOR_CELL_MAX];
static lte_cellinfo_t g_getcell =
{
  .neighbors = g_neighbors
}
;
static void *g_getcellargs[] =
{
  &g_getcellret, &g_getcell
};

/* event argument for LTE_CMDID_GETRAT */

static int g_getratret;
static void *g_getratargs[] =
{
  &g_getratret
};

/* event argument for LTE_CMDID_SETRAT */

static int g_setratret;
static void *g_setratargs[] =
{
  &g_setratret
};

/* event argument for LTE_CMDID_GETRATINFO */

static int g_getratinforet;
static lte_ratinfo_t g_ratinfo;
static void *g_getratinfoargs[] =
{
  &g_getratinforet, &g_ratinfo
};

/* event argument for LTE_CMDID_REPNETINFO */

static lte_pdn_t g_reppdninfo[LTE_SESSION_ID_MAX];
static lte_netinfo_t g_repnetinfo =
{
  .pdn_stat = g_reppdninfo
};

static uint8_t g_ndnsaddrs;
static struct sockaddr_storage g_dnsaddrs[ALTCOM_DNS_SERVERS];
static void *g_repnetinfoargs[] =
{
  &g_repnetinfo, &g_ndnsaddrs, g_dnsaddrs
};

/* event argument for LTE_CMDID_REPSIMSTAT and LTE_CMDID_REPLTIME */

static uint8_t g_repevtflag;
static uint32_t g_repsimstat;
static lte_localtime_t g_repltime;
static void *g_repevtargs[] =
{
  &g_repevtflag, &g_repsimstat, &g_repltime
};

/* event argument for LTE_CMDID_REPQUAL */

static lte_quality_t g_repqual;
static void *g_repqualargs[] =
{
  &g_repqual
};

/* event argument for LTE_CMDID_REPCELL */

static lte_neighbor_cell_t g_repneighbors[LTE_NEIGHBOR_CELL_MAX];
static lte_cellinfo_t g_repcell =
{
  .neighbors = g_repneighbors
};

static void *g_repcellargs[] =
{
  &g_repcell
};

/* event argument for LTE_CMDID_GETERRINFO */

static lte_errinfo_t g_geterrinfo;
static void *g_geterrinfoargs[] =
{
  &g_geterrinfo
};

/* event argument for LTE_CMDID_SELECT */

static int32_t g_selectret;
static int32_t g_selecterr;
static int32_t g_selectid;
static altcom_fd_set g_readset;
static altcom_fd_set g_writeset;
static altcom_fd_set g_exceptset;
static void *g_selectargs[] =
{
  &g_selectret, &g_selecterr, &g_selectid, &g_readset, &g_writeset,
  &g_exceptset
};

static struct alt_evtbuffer_s g_evtbuff;
static struct alt_evtbuf_inst_s g_evtbuffers[] =
{
  TABLE_CONTENT(SETRESTART, POWER_ON, g_setrestartargs),
  TABLE_CONTENT(GETVER, GET_VERSION, g_getverargs),
  TABLE_CONTENT(RADIOON, RADIO_ON, g_radioonargs),
  TABLE_CONTENT(RADIOOFF, RADIO_OFF, g_radiooffargs),
  TABLE_CONTENT(ACTPDN, ACTIVATE_PDN, g_actpdnargs),
  TABLE_CONTENT(DEACTPDN, DEACTIVATE_PDN, g_deactpdnargs),
  TABLE_CONTENT(GETNETINFO, GET_NETINFO, g_netinfoargs),
  TABLE_CONTENT(IMSCAP, GET_IMS_CAP, g_imscapargs),
  TABLE_CONTENT(GETPHONE, GET_PHONENO, g_getphoneargs),
  TABLE_CONTENT(GETIMSI, GET_IMSI, g_getimsiargs),
  TABLE_CONTENT(GETIMEI, GET_IMEI, g_getimeiargs),
  TABLE_CONTENT(GETPINSET, GET_PINSET, g_getpinsetargs),
  TABLE_CONTENT(PINENABLE, SET_PIN_LOCK, g_pinenableargs),
  TABLE_CONTENT(CHANGEPIN, SET_PIN_CODE, g_changepinargs),
  TABLE_CONTENT(ENTERPIN, ENTER_PIN, g_enterpinargs),
  TABLE_CONTENT(GETLTIME, GET_LTIME, g_getltimeargs),
  TABLE_CONTENT(GETOPER, GET_OPERATOR, g_getoperargs),
  TABLE_CONTENT(GETEDRX, GET_EDRX, g_getedrxargs),
  TABLE_CONTENT(SETEDRX, SET_EDRX, g_setedrxargs),
  TABLE_CONTENT(GETPSM, GET_PSM, g_getpsmargs),
  TABLE_CONTENT(SETPSM, SET_PSM, g_setpsmargs),
  TABLE_CONTENT(GETCE, GET_CE, g_getceargs),
  TABLE_CONTENT(SETCE, SET_CE, g_setceargs),
  TABLE_CONTENT(GETSIMINFO, GET_SIMINFO, g_getsiminfoargs),
  TABLE_CONTENT(GETCEDRX, GET_DYNAMICEDRX, g_getcedrxargs),
  TABLE_CONTENT(GETCPSM, GET_DYNAMICPSM, g_getcpsmargs),
  TABLE_CONTENT(GETQUAL, GET_QUALITY, g_getqualargs),
  TABLE_CONTENT(GETCELL, GET_CELLINFO, g_getcellargs),
  TABLE_CONTENT(GETRAT, GET_RAT, g_getratargs),
  TABLE_CONTENT(SETRAT, SET_RAT, g_setratargs),
  TABLE_CONTENT(GETRATINFO, GET_RAT, g_getratinfoargs),
  TABLE_CONTENT(REPNETINFO, REPORT_NETINFO, g_repnetinfoargs),
  TABLE_CONTENT(REPSIMSTAT, REPORT_EVT, g_repevtargs),
  TABLE_CONTENT(REPLTIME, REPORT_EVT, g_repevtargs),
  TABLE_CONTENT(REPQUAL, REPORT_QUALITY, g_repqualargs),
  TABLE_CONTENT(REPCELL, REPORT_CELLINFO, g_repcellargs),
  TABLE_CONTENT(GETERRINFO, ERRINFO, g_geterrinfoargs),
  TABLE_CONTENT(SELECT, SOCK_SELECT, g_selectargs),
};

static struct cbinfo_s g_execbtable[] =
{
  {LTE_CMDID_SETRESTART, lte_set_report_restart_exec_cb},
  {LTE_CMDID_GETVER, lte_get_version_exec_cb},
  {LTE_CMDID_RADIOON, lte_radio_on_exec_cb},
  {LTE_CMDID_RADIOOFF, lte_radio_off_exec_cb},
  {LTE_CMDID_ACTPDN, lte_activate_pdn_exec_cb},
  {LTE_CMDID_DEACTPDN, lte_deactivate_pdn_exec_cb},
  {LTE_CMDID_GETNETINFO, lte_get_netinfo_exec_cb},
  {LTE_CMDID_IMSCAP, lte_get_imscap_exec_cb},
  {LTE_CMDID_GETPHONE, lte_get_phoneno_exec_cb},
  {LTE_CMDID_GETIMSI, lte_get_imsi_exec_cb},
  {LTE_CMDID_GETIMEI, lte_get_imei_exec_cb},
  {LTE_CMDID_GETPINSET, lte_get_pinset_exec_cb},
  {LTE_CMDID_PINENABLE, lte_set_pinenable_exec_cb},
  {LTE_CMDID_CHANGEPIN, lte_change_pin_exec_cb},
  {LTE_CMDID_ENTERPIN, lte_enter_pin_exec_cb},
  {LTE_CMDID_GETLTIME, lte_get_localtime_exec_cb},
  {LTE_CMDID_GETOPER, lte_get_operator_exec_cb},
  {LTE_CMDID_GETEDRX, lte_get_edrx_exec_cb},
  {LTE_CMDID_SETEDRX, lte_set_edrx_exec_cb},
  {LTE_CMDID_GETPSM, lte_get_psm_exec_cb},
  {LTE_CMDID_SETPSM, lte_set_psm_exec_cb},
  {LTE_CMDID_GETCE, lte_get_ce_exec_cb},
  {LTE_CMDID_SETCE, lte_set_ce_exec_cb},
  {LTE_CMDID_GETSIMINFO, lte_get_siminfo_exec_cb},
  {LTE_CMDID_GETCEDRX, lte_get_current_edrx_exec_cb},
  {LTE_CMDID_GETCPSM, lte_get_current_psm_exec_cb},
  {LTE_CMDID_GETQUAL, lte_get_quality_exec_cb},
  {LTE_CMDID_REPNETINFO, lte_set_report_netinfo_exec_cb},
  {LTE_CMDID_REPSIMSTAT, lte_set_reportevt_exec_cb},
  {LTE_CMDID_REPLTIME, lte_set_reportevt_exec_cb},
  {LTE_CMDID_REPQUAL, lte_set_report_quality_exec_cb},
  {LTE_CMDID_REPCELL, lte_set_report_cellinfo_exec_cb},
};

static struct cbinfo_s g_cbtable[NCBTABLES];
static sem_t g_cbtablelock;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static uint64_t lte_set_report_restart_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  restart_report_cb_t callback = (restart_report_cb_t)cb;
  FAR uint32_t *param = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*param);
    }

  return 0ULL;
}

static uint64_t lte_radio_on_exec_cb(FAR void *cb, FAR void **cbarg)
{
  radio_on_cb_t callback = (radio_on_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_radio_off_exec_cb(FAR void *cb, FAR void **cbarg)
{
  radio_off_cb_t callback = (radio_off_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_activate_pdn_exec_cb(FAR void *cb, FAR void **cbarg)
{
  activate_pdn_cb_t callback = (activate_pdn_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_pdn_t *pdn = (FAR lte_pdn_t *)cbarg[1];

  if (callback)
    {
      callback(*result, pdn);
    }

  return 0ULL;
}

static uint64_t lte_deactivate_pdn_exec_cb(FAR void *cb, FAR void **cbarg)
{
  deactivate_pdn_cb_t callback = (deactivate_pdn_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_get_netinfo_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_netinfo_cb_t callback = (get_netinfo_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_netinfo_t *info = (FAR lte_netinfo_t *)cbarg[1];

  if (callback)
    {
      callback(*result, info);
    }

  return 0ULL;
}

static uint64_t lte_get_imscap_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_imscap_cb_t callback = (get_imscap_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR bool *imscap = (FAR bool *)cbarg[1];

  if (callback)
    {
      callback(*result, *imscap);
    }

  return 0ULL;
}

static uint64_t lte_get_version_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_ver_cb_t callback = (get_ver_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_version_t *version = (FAR lte_version_t *)cbarg[1];

  if (callback)
    {
      callback(*result, version);
    }

  return 0ULL;
}

static uint64_t lte_get_phoneno_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_phoneno_cb_t callback = (get_phoneno_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR uint8_t *errcause = (FAR uint8_t *)cbarg[1];
  FAR char *phoneno = (FAR char *)cbarg[2];

  if (callback)
    {
      callback(*result, *errcause, phoneno);
    }

  return 0ULL;
}

static uint64_t lte_get_imsi_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_imsi_cb_t callback = (get_imsi_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR uint8_t *errcause = (FAR uint8_t *)cbarg[1];
  FAR char *imsi = (FAR char *)cbarg[2];

  if (callback)
    {
      callback(*result, *errcause, imsi);
    }

  return 0ULL;
}

static uint64_t lte_get_imei_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_imei_cb_t callback = (get_imei_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR char *imei = (FAR char *)cbarg[1];

  if (callback)
    {
      callback(*result, imei);
    }

  return 0ULL;
}

static uint64_t lte_get_pinset_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_pinset_cb_t callback = (get_pinset_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_getpin_t *pinset = (FAR lte_getpin_t *)cbarg[1];

  if (callback)
    {
      callback(*result, pinset);
    }

  return 0ULL;
}

static uint64_t lte_set_pinenable_exec_cb(FAR void *cb, FAR void **cbarg)
{
  set_pinenable_cb_t callback = (set_pinenable_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR uint8_t *attemptsleft = (FAR uint8_t *)cbarg[1];

  if (callback)
    {
      callback(*result, *attemptsleft);
    }

  return 0ULL;
}

static uint64_t lte_change_pin_exec_cb(FAR void *cb, FAR void **cbarg)
{
  change_pin_cb_t callback = (change_pin_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR uint8_t *attemptsleft = (FAR uint8_t *)cbarg[1];

  if (callback)
    {
      callback(*result, *attemptsleft);
    }

  return 0ULL;
}

static uint64_t lte_enter_pin_exec_cb(FAR void *cb, FAR void **cbarg)
{
  enter_pin_cb_t callback = (enter_pin_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR uint8_t *simstat = (FAR uint8_t *)cbarg[1];
  FAR uint8_t *attemptsleft = (FAR uint8_t *)cbarg[2];

  if (callback)
    {
      callback(*result, *simstat, *attemptsleft);
    }

  return 0ULL;
}

static uint64_t lte_get_localtime_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_localtime_cb_t callback = (get_localtime_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_localtime_t *localtime = (FAR lte_localtime_t *)cbarg[1];

  if (callback)
    {
      callback(*result, localtime);
    }

  return 0ULL;
}

static uint64_t lte_get_operator_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_operator_cb_t callback = (get_operator_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR char *oper = (FAR char *)cbarg[1];

  if (callback)
    {
      callback(*result, oper);
    }

  return 0ULL;
}

static uint64_t lte_get_edrx_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_edrx_cb_t callback = (get_edrx_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_edrx_setting_t *settings = (FAR lte_edrx_setting_t *)cbarg[1];
  FAR bool *is_getedrxevt = (FAR bool *)cbarg[2];

  if (!(*is_getedrxevt))
    {
      return alt1250_evt_search(LTE_CMDID_GETCEDRX);
    }

  if (callback)
    {
      callback(*result, settings);
      *is_getedrxevt = false;
    }

  return 0ULL;
}

static uint64_t lte_set_edrx_exec_cb(FAR void *cb, FAR void **cbarg)
{
  set_edrx_cb_t callback = (set_edrx_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_get_psm_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_psm_cb_t callback = (get_psm_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_psm_setting_t *settings = (FAR lte_psm_setting_t *)cbarg[1];
  FAR bool *is_getpsmevt = (FAR bool *)cbarg[2];

  if (!(*is_getpsmevt))
    {
      return alt1250_evt_search(LTE_CMDID_GETCPSM);
    }

  if (callback)
    {
      callback(*result, settings);
      *is_getpsmevt = false;
    }

  return 0ULL;
}

static uint64_t lte_set_psm_exec_cb(FAR void *cb, FAR void **cbarg)
{
  set_psm_cb_t callback = (set_psm_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_get_ce_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_ce_cb_t callback = (get_ce_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_ce_setting_t *settings = (FAR lte_ce_setting_t *)cbarg[1];

  if (callback)
    {
      callback(*result, settings);
    }

  return 0ULL;
}

static uint64_t lte_set_ce_exec_cb(FAR void *cb, FAR void **cbarg)
{
  set_ce_cb_t callback = (set_ce_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*result);
    }

  return 0ULL;
}

static uint64_t lte_get_siminfo_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_siminfo_cb_t callback = (get_siminfo_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_siminfo_t *siminfo = (FAR lte_siminfo_t *)cbarg[1];

  if (callback)
    {
      callback(*result, siminfo);
    }

  return 0ULL;
}

static uint64_t lte_get_current_edrx_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_current_edrx_cb_t callback = (get_current_edrx_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_edrx_setting_t *settings = (FAR lte_edrx_setting_t *)cbarg[1];
  FAR bool *is_getcedrxevt = (FAR bool *)cbarg[2];

  if (!(*is_getcedrxevt))
    {
      return alt1250_evt_search(LTE_CMDID_GETEDRX);
    }

  if (callback)
    {
      callback(*result, settings);
      *is_getcedrxevt = false;
    }

  return 0ULL;
}

static uint64_t lte_get_current_psm_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_current_psm_cb_t callback = (get_current_psm_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_psm_setting_t *settings = (FAR lte_psm_setting_t *)cbarg[1];
  FAR bool *is_getcpsmevt = (FAR bool *)cbarg[2];

  if (!(*is_getcpsmevt))
    {
      return alt1250_evt_search(LTE_CMDID_GETPSM);
    }

  if (callback)
    {
      callback(*result, settings);
      *is_getcpsmevt = false;
    }

  return 0ULL;
}

static uint64_t lte_get_quality_exec_cb(FAR void *cb, FAR void **cbarg)
{
  get_quality_cb_t callback = (get_quality_cb_t)cb;
  FAR uint32_t *result = (FAR uint32_t *)cbarg[0];
  FAR lte_quality_t *quality = (FAR lte_quality_t *)cbarg[1];

  if (callback)
    {
      callback(*result, quality);
    }

  return 0ULL;
}

static uint64_t lte_set_report_netinfo_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  netinfo_report_cb_t callback = (netinfo_report_cb_t)cb;
  FAR lte_netinfo_t *info = (FAR lte_netinfo_t *)cbarg[0];
  FAR uint8_t ndnsaddrs = *((FAR uint8_t *)cbarg[1]);
  FAR struct sockaddr_storage *dnsaddr =
    (FAR struct sockaddr_storage *)cbarg[2];
#if defined(CONFIG_NETDB_DNSCLIENT)
  socklen_t addrlen;
  uint8_t i;
#endif

#if defined(CONFIG_NETDB_DNSCLIENT)
  DEBUGASSERT(ndnsaddrs <= ALTCOM_DNS_SERVERS);

  ndnsaddrs = (ndnsaddrs > ALTCOM_DNS_SERVERS) ?
    ALTCOM_DNS_SERVERS : ndnsaddrs;

  for (i = 0; (i < ndnsaddrs) && (i < CONFIG_NETDB_DNSSERVER_NAMESERVERS);
    i++)
    {
      addrlen = (dnsaddr[i].ss_family == AF_INET) ?
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
      dns_add_nameserver((FAR const struct sockaddr *)&dnsaddr[i], addrlen);
    }
#endif

  if (callback)
    {
      callback(info);
    }

  return 0ULL;
}

static uint64_t lte_set_report_simstat_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  simstat_report_cb_t callback = (simstat_report_cb_t)cb;
  FAR uint32_t *simstat = (FAR uint32_t *)cbarg[0];

  if (callback)
    {
      callback(*simstat);
    }

  return 0ULL;
}

static uint64_t lte_set_report_localtime_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  localtime_report_cb_t callback = (localtime_report_cb_t)cb;
  FAR lte_localtime_t *localtime = (FAR lte_localtime_t *)cbarg[0];

  if (callback)
    {
      callback(localtime);
    }

  return 0ULL;
}

static uint64_t lte_set_reportevt_exec_cb(FAR void *cb, FAR void **cbarg)
{
  FAR void *func = NULL;
  uint8_t flag = *((FAR uint8_t *)cbarg[0]);

  if (flag & ALTCOM_REPEVT_FLAG_SIMSTAT)
    {
      flag &= ~ALTCOM_REPEVT_FLAG_SIMSTAT;
      func = get_cbfunc(LTE_CMDID_REPSIMSTAT);
      lte_set_report_simstat_exec_cb(func, &cbarg[1]);
    }

  if (flag & ALTCOM_REPEVT_FLAG_LTIME)
    {
      flag &= ~ALTCOM_REPEVT_FLAG_LTIME;
      func = get_cbfunc(LTE_CMDID_REPLTIME);
      lte_set_report_localtime_exec_cb(func, &cbarg[2]);
    }

  return 0ULL;
}

static uint64_t lte_set_report_quality_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  quality_report_cb_t callback = (quality_report_cb_t)cb;
  FAR lte_quality_t *quality = (FAR lte_quality_t *)cbarg[0];

  if (callback)
    {
      callback(quality);
    }

  return 0ULL;
}

static uint64_t lte_set_report_cellinfo_exec_cb(FAR void *cb,
  FAR void **cbarg)
{
  cellinfo_report_cb_t callback = (cellinfo_report_cb_t)cb;
  FAR lte_cellinfo_t *cellinfo = (FAR lte_cellinfo_t *)cbarg[0];

  if (callback)
    {
      callback(cellinfo);
    }

  return 0ULL;
}

/****************************************************************************
 * Name: evtbuffer_init
 ****************************************************************************/

static void evtbuffer_init(int fd)
{
  int ret;
  int i;

  for (i = 0; i < ARRAY_SZ(g_evtbuffers); i++)
    {
      sem_init(&g_evtbuffers[i].stat_lock, 0, 1);
      g_evtbuffers[i].stat = ALTEVTBUF_ST_WRITABLE;
    }

  g_evtbuff.ninst = ARRAY_SZ(g_evtbuffers);
  g_evtbuff.inst = g_evtbuffers;

  ret = ioctl(fd, ALT1250_IOC_SETEVTBUFF, (unsigned long)&g_evtbuff);
  ASSERT(0 == ret);
}

/****************************************************************************
 * Name: clear_callback
 ****************************************************************************/

static void clear_callback(uint32_t cmdid)
{
  int i;

  for (i = 0; i < ARRAY_SZ(g_cbtable); i++)
    {
      if (g_cbtable[i].cmdid == cmdid)
        {
          g_cbtable[i].cmdid = 0;
          g_cbtable[i].cb = NULL;
          break;
        }
    }
}

/****************************************************************************
 * Name: errno2result
 ****************************************************************************/

static void errno2result(FAR int32_t *result_ptr)
{
  if (result_ptr && *result_ptr < 0)
    {
      if (*result_ptr == -ECANCELED)
        {
          *result_ptr = LTE_RESULT_CANCEL;
        }
      else
        {
          *result_ptr = LTE_RESULT_ERROR;
        }
    }
}

/****************************************************************************
 * Name: exec_callback
 ****************************************************************************/

static uint64_t exec_callback(uint32_t cmdid,
  uint64_t (*func)(FAR void *cb, FAR void **arg), FAR void **arg)
{
  int i;
  uint64_t evtbitmap = 0ULL;
  FAR int32_t *result = NULL;

  for (i = 0; i < ARRAY_SZ(g_cbtable); i++)
    {
      /* APIs that have result as a callback argument
       * change the value before execution.
       */

      if (g_cbtable[i].cmdid == cmdid)
        {
          if (!IS_REPORT_API(cmdid))
            {
              result = (int32_t *)arg[0];
              errno2result(result);
            }

          evtbitmap = func(g_cbtable[i].cb, arg);
          return evtbitmap;
        }
    }

  /* When callback is not found,
   * GETPSM and GETEDRX will execute func() and update the evtbitmap
   */

  if (cmdid == LTE_CMDID_GETPSM || cmdid == LTE_CMDID_GETEDRX)
    {
      evtbitmap = func(NULL, arg);
    }

  return evtbitmap;
}

/****************************************************************************
 * Name: get_evtarg
 ****************************************************************************/

static FAR void **get_evtarg(int idx)
{
  FAR alt_evtbuf_inst_t *inst = &g_evtbuffers[idx];

  return inst->outparam;
}

/****************************************************************************
 * Name: get_cmdid_byidx
 ****************************************************************************/

static FAR uint32_t get_cmdid_byidx(int idx)
{
  FAR alt_evtbuf_inst_t *inst = &g_evtbuffers[idx];

  return inst->cmdid;
}

/****************************************************************************
 * Name: update_evtarg_writable
 ****************************************************************************/

static void update_evtarg_writable(int idx)
{
  FAR alt_evtbuf_inst_t *inst = &g_evtbuffers[idx];

  sem_wait(&inst->stat_lock);

  inst->stat = ALTEVTBUF_ST_WRITABLE;

  sem_post(&inst->stat_lock);
}

/****************************************************************************
 * Name: get_execfunc
 ****************************************************************************/

static void *get_execfunc(int idx)
{
  int i;
  uint32_t cmdid;

  cmdid = get_cmdid_byidx(idx);

  for (i = 0; i < ARRAY_SZ(g_execbtable); i++)
    {
      if (g_execbtable[i].cmdid == cmdid)
        {
          return g_execbtable[i].cb;
        }
    }

  return NULL;
}

/****************************************************************************
 * Name: get_cbfunc
 ****************************************************************************/

static void *get_cbfunc(uint32_t cmdid)
{
  int i;

  for (i = 0; i < ARRAY_SZ(g_cbtable); i++)
    {
      if (g_cbtable[i].cmdid == cmdid)
        {
          return g_cbtable[i].cb;
        }
    }

  return NULL;
}

/****************************************************************************
 * Name: alt1250_search_execcb
 ****************************************************************************/

static uint64_t alt1250_search_execcb(uint64_t evtbitmap)
{
  int idx;
  uint64_t l_evtbitmap = 0ULL;
  uint64_t (*func)(FAR void *cb, FAR void **arg);

  for (idx = 0; idx < ARRAY_SZ(g_evtbuffers); idx++)
    {
      if (evtbitmap & (1ULL << idx))
        {
          alt1250_printf("idx=%d\n", idx);

          sem_wait(&g_cbtablelock);

          func = get_execfunc(idx);
          l_evtbitmap |= exec_callback(g_evtbuffers[idx].cmdid, func,
            get_evtarg(idx));

          if (l_evtbitmap == 0ULL)
            {
              if (LTE_ISCMDGRP_NORMAL(g_evtbuffers[idx].cmdid))
                {
                  clear_callback(g_evtbuffers[idx].cmdid);
                }
            }

          sem_post(&g_cbtablelock);

          if (l_evtbitmap == 0ULL)
            {
              update_evtarg_writable(idx);
            }
        }
    }

  alt1250_printf("evtbitmap=0x%llx\n", l_evtbitmap);

  return l_evtbitmap;
}

/****************************************************************************
 * Name: alt1250_search_execcb
 ****************************************************************************/

static uint64_t alt1250_evt_search(uint32_t cmdid)
{
  int idx;

  uint64_t evtbitmap = 0ULL;

  for (idx = 0; idx < ARRAY_SZ(g_evtbuffers); idx++)
    {
      if (g_evtbuffers[idx].cmdid == cmdid)
        {
          evtbitmap = (1ULL << idx);
        }
    }

  return evtbitmap;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: alt1250_setevtbuff
 ****************************************************************************/

int alt1250_setevtbuff(int altfd)
{
  sem_init(&g_cbtablelock, 0, 1);
  evtbuffer_init(altfd);

  return 0;
}

/****************************************************************************
 * Name: alt1250_evtdestroy
 ****************************************************************************/

int alt1250_evtdestroy(void)
{
  sem_destroy(&g_cbtablelock);

  return 0;
}

/****************************************************************************
 * Name: alt1250_regevtcb
 ****************************************************************************/

int alt1250_regevtcb(uint32_t cmdid, FAR void *cb)
{
  int ret = OK;
  int i;
  bool is_clear = (cb == NULL);
  int myidx = -1;
  int freeidx = -1;

  sem_wait(&g_cbtablelock);

  for (i = 0; i < ARRAY_SZ(g_cbtable); i++)
    {
      if (g_cbtable[i].cmdid == 0)
        {
          freeidx = i;
        }

      if (g_cbtable[i].cmdid == cmdid)
        {
          myidx = i;
          break;
        }
    }

  if (!is_clear)
    {
      /* Found my ID */

      if (myidx != -1)
        {
          ret = -EALREADY;
        }

      /* No free index at table? */

      else if (freeidx == -1)
        {
          ret = -EBUSY;
        }

      /* Not found my ID, but found a free index. */

      else
        {
          g_cbtable[freeidx].cmdid = cmdid;
          g_cbtable[freeidx].cb = cb;
        }
    }
  else
    {
      /* Not found my ID */

      if (myidx == -1)
        {
          ret = -EALREADY;
        }

      /* Found my ID */

      else
        {
          g_cbtable[myidx].cmdid = 0;
          g_cbtable[myidx].cb = NULL;
        }
    }

  sem_post(&g_cbtablelock);

  return ret;
}

/****************************************************************************
 * Name: alt1250_execcb
 ****************************************************************************/

void alt1250_execcb(uint64_t evtbitmap)
{
  uint64_t l_evtbitmap = 0ULL;

  l_evtbitmap = alt1250_search_execcb(evtbitmap);

  if (l_evtbitmap != 0ULL)
    {
      alt1250_search_execcb(l_evtbitmap);
    }
}

/****************************************************************************
 * Name: alt1250_getevtarg
 ****************************************************************************/

FAR void **alt1250_getevtarg(uint32_t cmdid)
{
  int i;

  for (i = 0; i < ARRAY_SZ(g_evtbuffers); i++)
    {
      if (g_evtbuffers[i].cmdid == cmdid)
        {
          return g_evtbuffers[i].outparam;
        }
    }

  return NULL;
}

/****************************************************************************
 * Name: alt1250_checkcmdid
 ****************************************************************************/

bool alt1250_checkcmdid(uint32_t cmdid, uint64_t evtbitmap,
  FAR uint64_t *bit)
{
  int idx;
  bool ret = false;

  for (idx = 0; idx < ARRAY_SZ(g_evtbuffers); idx++)
    {
      if (evtbitmap & (1ULL << idx))
        {
          alt1250_printf("idx=%d\n", idx);

          if (g_evtbuffers[idx].cmdid == cmdid)
            {
              ret = true;
              *bit = 1ULL << idx;
              break;
            }
        }
    }

  return ret;
}

/****************************************************************************
 * Name: alt1250_setevtarg_writable
 ****************************************************************************/

void alt1250_setevtarg_writable(uint32_t cmdid)
{
  int idx;
  FAR alt_evtbuf_inst_t *inst = NULL;

  for (idx = 0; idx < ARRAY_SZ(g_evtbuffers); idx++)
    {
      if (g_evtbuffers[idx].cmdid == cmdid)
        {
          inst = &g_evtbuffers[idx];

          sem_wait(&inst->stat_lock);

          inst->stat = ALTEVTBUF_ST_WRITABLE;

          sem_post(&inst->stat_lock);

          break;
        }
    }
}

/****************************************************************************
 * Name: alt1250_clrevtcb
 ****************************************************************************/

int alt1250_clrevtcb(uint8_t mode)
{
  int ret = OK;
  int i;

  sem_wait(&g_cbtablelock);

  if (mode == ALT1250_CLRMODE_WO_RESTART)
    {
      for (i = 0; i < ARRAY_SZ(g_cbtable); i++)
        {
          if (g_cbtable[i].cmdid != LTE_CMDID_SETRESTART)
            {
              g_cbtable[i].cb = NULL;
              g_cbtable[i].cmdid = 0;
            }
        }
    }
  else if (mode == ALT1250_CLRMODE_ALL)
    {
      memset(g_cbtable, 0, sizeof(struct cbinfo_s) * NCBTABLES);
    }
  else
    {
      ret = -EINVAL;
    }

  sem_post(&g_cbtablelock);

  return ret;
}
