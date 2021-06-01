/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 *
 * mod_xml_m2_radius.c -- M2 Radius authentication and accounting
 *
 */

#include <switch.h>
#include <switch_event.h>
#include <sys/stat.h>
#include <freeradius-client.h>

#define M2_VERSION "0.0.29"

// global variables

static struct {
    switch_xml_t m2_radius_auth_conf;
    switch_xml_t m2_radius_acct_start_conf;
    switch_xml_t m2_radius_acct_stop_conf;
} config = {0};

int use_secondary_connection = 0;

static char m2_radius_config[256] = "xml_m2_radius.conf";

SWITCH_MODULE_LOAD_FUNCTION(mod_xml_m2_radius_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xml_m2_radius_shutdown);
SWITCH_MODULE_DEFINITION(mod_xml_m2_radius, mod_xml_m2_radius_load, mod_xml_m2_radius_shutdown, NULL);

// radius client handle initialization

static rc_handle *m2_radius_init(switch_xml_t conf_xml, int auth, int secondary_connection) {

    char m2_radius_dictionary[512];
    char m2_radius_deadtime[512];
    char m2_radius_timeout[512];
    char m2_radius_retries[512];
    char m2_radius_server[512];
    switch_xml_t connection;
    switch_xml_t param;
    rc_handle *rh;
    char connection_type[256] = "m2_radius_connection";

    if (secondary_connection) {
        strcpy(connection_type, "m2_radius_secondary_connection");
    }

    // create new radius client handle
    rh = rc_new();

    if (rh == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Error initializing rc_handle!\n");
        return NULL;
    }

    // default values
    strncpy(m2_radius_timeout, "5", 511);
    strncpy(m2_radius_retries, "3", 511);
    strncpy(m2_radius_deadtime, "0", 511);
    strncpy(m2_radius_server, "127.0.0.1", 511);
    strncpy(m2_radius_dictionary, "/usr/local/freeswitch/conf/radius/dictionary", 511);

    // get actual values
    if ((connection = switch_xml_child(conf_xml, connection_type))) {
        for (param = switch_xml_child(connection, "param"); param; param = param->next) {

            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if (!strcmp(var, "server")) {
                strncpy(m2_radius_server, val, 511);
            } else if (!strcmp(var, "dictionary")) {
                strncpy(m2_radius_dictionary, val, 511);
            } else if (!strcmp(var, "timeout")) {
                strncpy(m2_radius_timeout, val, 511);
            } else if (!strcmp(var, "retries")) {
                strncpy(m2_radius_retries, val, 511);
            } else if (!strcmp(var, "deadtime")) {
                strncpy(m2_radius_deadtime, val, 511);
            }

        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Connection settings not found (%s)\n", connection_type);
        return NULL;
    }

    rh = rc_config_init(rh);

    if (rh == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Error initializing radius config!\n");
        rc_destroy(rh);
        return NULL;
    }

    // add configs to rh (radius client handle)

    if (rc_add_config(rh, "auth_order", "radius", "mod_xml_m2_radius.c", 0) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting auth_order = radius failed\n");
        rc_destroy(rh);
        return NULL;
    }

    if (!auth) {
        if (rc_add_config(rh, "acctserver", m2_radius_server, m2_radius_config, 0) != 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting acctserver = %s failed\n", m2_radius_server);
            rc_destroy(rh);
            return NULL;
        }
    } else {
        if (rc_add_config(rh, "authserver", m2_radius_server, m2_radius_config, 0) != 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting authserver = %s failed\n", m2_radius_server);
            rc_destroy(rh);
            return NULL;
        }
    }

    if (rc_add_config(rh, "dictionary", m2_radius_dictionary, m2_radius_config, 0) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting dictionary = %s failed\n", m2_radius_dictionary);
        rc_destroy(rh);
        return NULL;
    }

    if (rc_add_config(rh, "radius_deadtime", m2_radius_deadtime, m2_radius_config, 0) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting radius_deadtime = %s failed\n", m2_radius_deadtime);
        rc_destroy(rh);
        return NULL;
    }

    if (rc_add_config(rh, "radius_timeout", m2_radius_timeout, m2_radius_config, 0) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting radius_timeout = %s failed\n", m2_radius_timeout);
        rc_destroy(rh);
        return NULL;
    }

    if (rc_add_config(rh, "radius_retries", m2_radius_retries, m2_radius_config, 0) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Setting radius_retries = %s failed\n", m2_radius_retries);
        rc_destroy(rh);
        return NULL;
    }

    // read the dictionary file(s)
    if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Error reading dictionary file(s): %s\n", m2_radius_dictionary);
        rc_destroy(rh);
        return NULL;
    }

    return rh;
}


/*
    Add params to rc handle
*/


switch_status_t m2_xml_radius_add_params(switch_core_session_t *session, rc_handle *rh, VALUE_PAIR **send, switch_xml_t xml_conf, char *uuid) {

    switch_xml_t param, fields;
    void *av_value = NULL;

    if ((fields = switch_xml_child(xml_conf, "fields")) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to locate a fields section:\n%s\n", uuid, switch_xml_toxml(xml_conf, 1));
        goto err;
    }

    if ((param = switch_xml_child(fields, "param")) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to locate a param section:\n%s\n", uuid, switch_xml_toxml(fields, 1));
        goto err;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] ------------------- Adding attribute-value pairs -------------------\n", uuid);

    for (; param; param = param->next) {

        DICT_ATTR *attribute = NULL;
        DICT_VENDOR *vendor = NULL;
        int attr_num = 0, vend_num = 0;

        char *var = (char *) switch_xml_attr(param, "name");
        char *vend = (char *) switch_xml_attr(param, "vendor");
        char *variable = (char *) switch_xml_attr(param, "variable");
        char *format = (char *) switch_xml_attr(param, "format");

        attribute = rc_dict_findattr(rh, var);

        if (attribute == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Could not locate attribute '%s' in the configured dictionary\n", uuid, var);
            goto err;
        }

        attr_num = attribute->value;

        // get vendor id
        if (vend) {
            vendor = rc_dict_findvend(rh, vend);
            if (vendor == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Could not locate vendor '%s' in the configured dictionary %p\n", uuid, vend, vend);
                goto err;
            }
            vend_num = vendor->vendorpec;
        }

        if (var) {
            if (session) {

                if (variable) {

                    switch_channel_t *channel = switch_core_session_get_channel(session);

                    if (format == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Missing format attribute for %s variable\n", uuid, variable);
                        goto err;
                    }

                    if (attribute->type == 0) {

                        const char *val = NULL;
                        char val_string[1000] = "";

                        val = switch_channel_get_variable(channel, variable);

                        if (val) {
                            strncpy(val_string, val, sizeof(val_string) - 1);

                            if (strcmp(variable, "ep_codec_string") == 0) {
                                strcpy(val_string, "");
                                if (strcasestr(val, "PCMU")) strcat(val_string, "PCMU,");
                                if (strcasestr(val, "PCMA")) strcat(val_string, "PCMA,");
                                if (strcasestr(val, "GSM")) strcat(val_string, "GSM,");
                                if (strcasestr(val, "OPUS")) strcat(val_string, "OPUS,");
                                if (strcasestr(val, "SPEEX")) strcat(val_string, "SPEEX,");
                                if (strcasestr(val, "LPC")) strcat(val_string, "LPC,");
                                if (strcasestr(val, "iLBC@30i")) strcat(val_string, "iLBC@30i,");
                                if (strcasestr(val, "G722")) strcat(val_string, "G722,");
                                if (strcasestr(val, "G723")) strcat(val_string, "G723,");
                                if (strcasestr(val, "G726-16")) strcat(val_string, "G726-16,");
                                if (strcasestr(val, "G729")) strcat(val_string, "G729,");
                            }

                            av_value = switch_mprintf(format, val_string);

                            if (rc_avpair_add(rh, send, attr_num, av_value, -1, vend_num) == NULL) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add option with val '%s' to rh\n", uuid, (char *) av_value);
                                goto err;
                            }
                        }

                        if (av_value) {
                            if (strcmp(var, "Cisco-AVPair")) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s=%s\n", uuid, var, (char *) av_value);
                            } else {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s\n", uuid, (char *) av_value);
                            }
                        }

                    } else if (attribute->type == 1) {
                        const char *str = NULL;
                        str = switch_channel_get_variable(channel, variable);
                        if (str) {
                            int number = atoi(str);
                            if (rc_avpair_add(rh, send, attr_num, &number, -1, vend_num) == NULL) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add option with value '%d' to rh\n", uuid, number);
                                goto err;
                            }
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s=%d\n", uuid, var, number);
                        } else {
                            // Skip warning message for 'billsec' variable
                            if (strcmp(variable, "billsec")) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "[m2_radius %s] Failed to parse variable '%s'\n", uuid, variable);
                            }
                        }

                    }
                }

            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] All params must have a name attribute\n", uuid);
            goto err;
        }

        if (av_value != NULL) {
            free(av_value);
            av_value = NULL;
        }

    }

    return SWITCH_STATUS_SUCCESS;

err:

    if (av_value != NULL) {
        free(av_value);
        av_value = NULL;
    }

    return SWITCH_STATUS_GENERR;

}


/*
    Read configs
*/


switch_status_t m2_radius_load_config() {

    switch_xml_t xml, tmp, cfg;

    memset(&config, 0, sizeof(config));

    if (!(xml = switch_xml_open_cfg(m2_radius_config, &cfg, NULL))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Open of %s failed\n", m2_radius_config);
        goto err;
    }

    if ((tmp = switch_xml_dup(switch_xml_child(cfg, "m2_radius_auth"))) != NULL ) {
        config.m2_radius_auth_conf = tmp;
    } else {
        goto err;
    }

    if ((tmp = switch_xml_dup(switch_xml_child(cfg, "m2_radius_acct_start"))) != NULL ) {
        config.m2_radius_acct_start_conf = tmp;
    } else {
        goto err;
    }

    if ((tmp = switch_xml_dup(switch_xml_child(cfg, "m2_radius_acct_stop"))) != NULL ) {
        config.m2_radius_acct_stop_conf = tmp;
    } else {
        goto err;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Configuration success\n");
    if (xml) {
        switch_xml_free(xml);
        xml = NULL;
    }

    return SWITCH_STATUS_SUCCESS;

 err:

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Configuration error\n");
    if (xml) {
        switch_xml_free(xml);
        xml = NULL;
    }

    return SWITCH_STATUS_GENERR;

}


static switch_status_t m2_radius_send_acct_packet(int acctstart, int failed, switch_core_session_t *session, char *leg_a_uuid, int hangupcause) {

    int result = 0;
    rc_handle *rh = NULL;
    VALUE_PAIR *send = NULL;
    switch_xml_t conf_xml = config.m2_radius_acct_start_conf;
    char acct_type[128] = "start";
    uint32_t service = PW_STATUS_START;
    switch_call_cause_t cause;
    switch_caller_profile_t *profile;
    switch_time_t callstartdate = 0;
    switch_time_t callanswerdate = 0;
    switch_time_t callenddate = 0;
    switch_time_t calltransferdate = 0;
    switch_time_t billusec = 0;
    switch_time_exp_t tm;
    char buffer[256] = "";
    switch_call_cause_t cause_q850;
    char uuid[256] = "";
    int sent_to_secondary_connection = 0;
    int init_secondary_connection = 0;
    char system_cmd[256] = "";
    const char *endpoint_disposition = NULL;

    if (leg_a_uuid && strlen(leg_a_uuid)) {
        strcpy(uuid, leg_a_uuid);
    }

    if (!acctstart) {
        strcpy(acct_type, "stop");
        conf_xml = config.m2_radius_acct_stop_conf;
        service = PW_STATUS_STOP;
    }

    if (session) {

        const char *val = NULL;
        const char *val_uuid = NULL;
        const char *val_partner_uuid = NULL;
        switch_channel_t *channel;

        channel = switch_core_session_get_channel(session);

        if (!channel) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] No channel\n", uuid);
            return 0;
        }

        val = switch_channel_get_variable(channel, "direction");
        if (!strlen(uuid)) {
            val_uuid = switch_channel_get_variable(channel, "uuid");
            if (val_uuid) {
                strcpy(uuid, val_uuid);
            }
        }

        if (val != NULL) {

            // check maybe originator cancelled
            const char *val_hgc= NULL;
            val_hgc = switch_channel_get_variable(channel, "proto_specific_hangup_cause");

            // if originator cancelled, then send acct stop packet even on legA channel (usually acct stop should be sent from legB channel)
            if (val_hgc && strcmp(val_hgc, "sip:487") == 0) {
                failed = 1;
            }

            // check only legB
            if (acctstart == 0 && strcmp(val, "outbound")) {
                endpoint_disposition = switch_channel_get_variable(channel, "endpoint_disposition");

                // if call failed before dialing legB, then allow legA
                // also allow legA on CODEC NEGOTIATION ERROR because legB does not have any info about this error
                if (!failed && strcmp(endpoint_disposition, "CODEC NEGOTIATION ERROR") != 0) {
                    return 0;
                }
            }

            val_partner_uuid = switch_channel_get_variable_partner(channel, "uuid");
            if (val_partner_uuid) {
                char old_uuid[256] = "";
                strcpy(old_uuid, uuid);
                strcpy(uuid, val_partner_uuid);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Other leg UUID: %s\n", uuid, old_uuid);
            }

            cause_q850 = switch_channel_get_cause_q850(channel);
            sprintf(buffer, "%d", cause_q850);
            switch_channel_set_variable_partner(channel, "m2_q850_hgc", buffer);

            // if we are doing core recompile, then we need to initialize 2 connections
            // one to old radius server and another to new radius server

            init_secondary_connection_label:

            if (init_secondary_connection) {
                sent_to_secondary_connection = 1;
                rh = m2_radius_init(conf_xml, 0, 1);
            } else {
                rh = m2_radius_init(conf_xml, 0, 0);
            }

            if (rh == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Pointer rh is NULL!\n", uuid);
                goto acct_err;
            }

            if (m2_xml_radius_add_params(session, rh, &send, conf_xml, uuid) != SWITCH_STATUS_SUCCESS ) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add params to rc_handle\n", uuid);
                goto acct_err;
            }

            if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &service, -1, 0) == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add option to handle\n", uuid);
                goto acct_err;
            }

            if (!acctstart) {
                const char *val2 = NULL;
                const char *val3 = NULL;
                const char *val4 = NULL;
                char *new_buffer = NULL;
                char tmp_buffer[256] = "";
                char sip_cause_buffer[256] = "";
                cause = switch_channel_get_cause(channel);
                new_buffer = switch_mprintf("%s", switch_channel_cause2str(cause));
                val2 = switch_channel_get_variable(channel, "originate_disposition");
                val3 = switch_channel_get_variable(channel, "proto_specific_hangup_cause");
                val4 = switch_channel_get_variable(channel, "last_bridge_proto_specific_hangup_cause");

                if (val2) {
                    if (cause == 0 && strcmp(new_buffer, "NONE") == 0) {
                        strcpy(tmp_buffer, val2);
                    }
                }

                if (val3) {
                    if (strcmp(new_buffer, "CALL_REJECTED") == 0 && strcmp(val3, "sip:603") == 0) {
                        strcpy(new_buffer, "USER_BUSY");
                    }
                }

                if (!strlen(tmp_buffer)) {
                    if (new_buffer) {
                        strcpy(tmp_buffer, new_buffer);
                    }
                }

                if (val3) {
                    sprintf(sip_cause_buffer, "terminator-sip-hangupcause=%s", val3);
                    if (rc_avpair_add(rh, &send, 1, sip_cause_buffer, -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add terminator-sip-hangupcause!\n", uuid);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s\n", uuid, sip_cause_buffer);
                    }
                }

                if (val4) {
                    strcpy(sip_cause_buffer, "");
                    sprintf(sip_cause_buffer, "originator-sip-hangupcause=%s", val4);
                    if (rc_avpair_add(rh, &send, 1, sip_cause_buffer, -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add originator-sip-hangupcause!\n", uuid);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s\n", uuid, sip_cause_buffer);
                    }
                }

                if (rc_avpair_add(rh, &send, 30, (void *)tmp_buffer, -1, 9) == NULL) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add h323-disconnect-cause: %d\n", uuid, cause);
                    if (new_buffer) {
                        free(new_buffer);
                        new_buffer = NULL;
                    }
                    goto acct_err;
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] h323-disconnect-cause = %s\n", uuid, (char *)tmp_buffer);
                }

                if (new_buffer) {
                    free(new_buffer);
                    new_buffer = NULL;
                }

                if (hangupcause) {
                    new_buffer = switch_mprintf("freeswitch-hangupcause=%d", hangupcause);
                } else {
                    new_buffer = switch_mprintf("freeswitch-hangupcause=%d", cause);
                }

                if (rc_avpair_add(rh, &send, 1, (void *)new_buffer, -1, 9) == NULL) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add freeswitch-hangupcause: %d\n", uuid, cause);
                    if (new_buffer) {
                        free(new_buffer);
                        new_buffer = NULL;
                    }
                    goto acct_err;
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s\n", uuid, new_buffer);
                }

                if (new_buffer) {
                    free(new_buffer);
                    new_buffer = NULL;
                }

                if (endpoint_disposition && strcmp(endpoint_disposition, "CODEC NEGOTIATION ERROR") == 0) {
                    if (rc_avpair_add(rh, &send, 1, "freeswitch-endpnt-disp=CODEC_NEGOTIATION_ERROR", -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add freeswitch-endpnt-disp=CODEC_NEGOTIATION_ERROR!\n", uuid);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] freeswitch-endpnt-disp=CODEC_NEGOTIATION_ERROR\n", uuid);
                    }
                }
            }

            // get time variables
            profile = switch_channel_get_caller_profile(channel);

            if (profile) {

                // calculate billable time
                callstartdate = profile->times->created;
                callanswerdate = profile->times->answered;
                calltransferdate = profile->times->transferred;
                callenddate = profile->times->hungup;

                if (switch_channel_test_flag(channel, CF_ANSWERED)) {
                    if (callstartdate && callanswerdate) {
                        if (callenddate)
                            billusec = callenddate - callanswerdate;
                        else if (calltransferdate)
                            billusec = calltransferdate - callanswerdate;
                    }
                } else if (switch_channel_test_flag(channel, CF_TRANSFER)) {
                    if (callanswerdate && calltransferdate)
                        billusec = calltransferdate - callanswerdate;
                }

                if (callstartdate > 0) {
                    switch_time_exp_lt(&tm, callstartdate);
                    switch_snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%06u%+03d%02d",
                                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                                    tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec, tm.tm_gmtoff / 3600, tm.tm_gmtoff % 3600);
                    if (rc_avpair_add(rh, &send, 25, &buffer, -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed adding h323-setup-time: %s\n", uuid, buffer);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] h323-setup-time=%s\n", uuid, (char *) buffer);
                    }
                }

                if (callanswerdate > 0) {
                    switch_time_exp_lt(&tm, callanswerdate);
                    switch_snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%06u%+03d%02d",
                                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                                    tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec, tm.tm_gmtoff / 3600, tm.tm_gmtoff % 3600);
                    if (rc_avpair_add(rh, &send, 28, &buffer, -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed adding h323-connect-time: %s\n", uuid, buffer);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] h323-connect-time=%s\n", uuid, (char *) buffer);
                    }
                }

                if (callenddate > 0) {
                    switch_time_exp_lt(&tm, callenddate);
                    switch_snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%06u%+03d%02d",
                                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                                    tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec, tm.tm_gmtoff / 3600, tm.tm_gmtoff % 3600);
                    if (rc_avpair_add(rh, &send, 29, &buffer, -1, 9) == NULL) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed adding h323-disconnect-time: %s\n", uuid, buffer);
                        goto acct_err;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] h323-disconnect-time=%s\n", uuid, (char *) buffer);
                    }
                }

            }

            result = rc_acct(rh, 0, send);

            if (!acctstart) {
                switch_channel_set_variable_partner(channel, "m2_attempt_processed", "true");
            }

            if (result != OK_RC) {
                char error_msg[256] = "UNKNOWN_ERROR";

                if (result == BADRESP_RC) {
                    strcpy(error_msg, "BADRESP_RC");
                } else if (result == ERROR_RC) {
                    strcpy(error_msg, "GENERAL_ERROR");
                } else if (result == TIMEOUT_RC) {
                    strcpy(error_msg, "TIMEOUT_RC");
                } else if (result == REJECT_RC) {
                    strcpy(error_msg, "REJECT_RC");
                }

                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Result (RC = %d) %s\n", uuid, result, error_msg);
                goto acct_err;
            }

            if (send) {
                rc_avpair_free(send);
                send = NULL;
            }

            if (rh) rc_destroy(rh);

            if (sent_to_secondary_connection) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Accounting [%s] successful (secondary connection)\n", uuid, acct_type);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Accounting [%s] successful\n", uuid, acct_type);
            }

            if (acctstart) {
                switch_channel_set_variable(channel, "m2_channel_answered", "1");
            }

            // if we are doing core recompile, then send one request to secondary radius server (only acct stop)
            if (sent_to_secondary_connection == 0 && use_secondary_connection) {
                init_secondary_connection = 1;
                sent_to_secondary_connection = 1;
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Sending secondary radius request\n");
                goto init_secondary_connection_label;
            }

            return 0;
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] No val\n", uuid);
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] No session\n", uuid);
    }

    acct_err:

    if (send) {
        rc_avpair_free(send);
        send = NULL;
    }

    if (rh) rc_destroy(rh);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Accounting [%s] error\n", uuid, acct_type);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Hanging up call with uniqueid: %s\n", uuid, uuid);

    sprintf(system_cmd, "fs_cli -x 'uuid_kill %s'", uuid);
    system(system_cmd);

    return 1;

}

static switch_status_t m2_radius_accounting_stop(switch_core_session_t *session) {

    if (m2_radius_send_acct_packet(0, 0, session, "", 0)) {
        return 1;
    }

    return 0;

}

static void m2_set_codec_variables(char *uuid) {

    switch_core_session_t *session = NULL;
    switch_channel_t *channel = NULL;
    const char *read_codec = NULL;
    const char *direction = NULL;
    const char *m2_bypass_media_enabled = NULL;
    char variable_name[128] = "";

    if ((session = switch_core_session_locate(uuid))) {
        channel = switch_core_session_get_channel(session);
        m2_bypass_media_enabled = switch_channel_get_variable(channel, "m2_bypass_media_enabled");

        if (m2_bypass_media_enabled && strcmp(m2_bypass_media_enabled, "true") == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Bypass media is enabled, codecs cannot be retrieved!\n", uuid);
            switch_core_session_rwunlock(session);
            return;
        }

        direction = switch_channel_get_variable(channel, "direction");

        if (direction && strlen(direction)) {
            sprintf(variable_name, "m2_%s_codec_read", direction);

            read_codec = switch_channel_get_variable(channel, "read_codec");
            if (read_codec) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s codec: %s\n", uuid, strcmp(direction, "inbound") == 0 ? "Originator" : "Terminator", read_codec);
                switch_channel_set_variable(channel, variable_name, read_codec);
                switch_channel_set_variable_partner(channel, variable_name, read_codec);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Call codec not found!\n", uuid);
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Call direction not found!\n", uuid);
        }

        switch_core_session_rwunlock(session);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Call session not found!\n", uuid);
    }

}

static void m2_radius_accounting_start(switch_event_t *event) {

    switch_core_session_t *session = NULL;
    switch_event_header_t *hp;
    char uuid[256] = "";
    char direction[256] = "";

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Initializing Accounting start packet\n");

    switch (event->event_id) {
    case SWITCH_EVENT_LOG:
        return;
    default:

        for (hp = event->headers; hp; hp = hp->next) {
            if (strcmp("Unique-ID", hp->name) == 0) {
                m2_set_codec_variables(hp->value);
            } else if (strcmp("Call-Direction", hp->name) == 0) {
                strcpy(direction, hp->value);
                if (strcmp(hp->value, "outbound") == 0) {
                    goto outbound;
                }
            }
        }

        if (!strlen(direction)) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Call direction not found\n");
        }

        return;

        outbound:

        for (hp = event->headers; hp; hp = hp->next) {
            if (strcmp("Channel-Call-UUID", hp->name) == 0) {
                strcpy(uuid, hp->value);
                break;
            }
        }

        if (!strlen(uuid)) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Call UUID not found!\n");
        }

        break;
    }

    if ((session = switch_core_session_locate(uuid))) {
        m2_radius_send_acct_packet(1, 0, session, uuid, 0);
        switch_core_session_rwunlock(session);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Call session not found by uuid (%s)!\n", uuid);
    }

}

static void m2_xml_radius_reload_event(switch_event_t *event) {

    if (m2_radius_load_config() != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Reload failed\n");
        return;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Conf file reloaded\n");

}


SWITCH_STANDARD_APP(m2_radius_auth_handle) {

    switch_channel_t *channel = NULL;
    int result = 0;
    VALUE_PAIR *send = NULL, *recv = NULL, *service_vp = NULL;
    char msg[512 * 10 + 1] = {0};
    uint32_t service = PW_AUTHENTICATE_ONLY;
    rc_handle *rh = NULL;
    char name[256] = "", value[256] = "";
    int route;
    int terminator;
    char uuid[256] = "";
    int annexb = 0;
    const char *val = NULL;

    channel = switch_core_session_get_channel(session);
    val = switch_channel_get_variable(channel, "uuid");
    if (val) {
        strcpy(uuid, val);
    }

    if (strstr(switch_channel_get_variable(channel, "switch_r_sdp"), "annexb=yes")) {
        annexb = 1;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Starting authentication\n", uuid);

    if (channel == NULL) {
        goto auth_err;
    }

    rh = m2_radius_init(config.m2_radius_auth_conf, 1, 0);

    if (rh == NULL) {
        goto auth_err;
    }

    if (m2_xml_radius_add_params(session, rh, &send, config.m2_radius_auth_conf, uuid) != SWITCH_STATUS_SUCCESS ) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add params to rc_handle\n", uuid);
        goto auth_err;
    }

    if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add option to handle\n", uuid);
        goto auth_err;
    }

    // if SDP contains Annex B, pass it to radius
    if (annexb) {
        if (rc_avpair_add(rh, &send, 1, "freeswitch-annexb=1", -1, 9) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to add freeswitch-annexb!\n", uuid);
            goto auth_err;
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] freeswitch-annexb=1\n", uuid);
        }
    }

    result = rc_auth(rh, 0, send, &recv, msg);

    if (result != OK_RC) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Result (RC = %d) %s\n", uuid, result, msg);
        goto auth_err;
    }

    // set channel variable with auth result
    switch_channel_set_variable(channel, "m2_auth_result", "1");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] ------------------- Received attribute-value pairs --------------------\n", uuid);

    service_vp = recv;
    route = 1;
    terminator = 1;
    while (service_vp != NULL) {
        memset(value, 0, sizeof(value));
        memset(name, 0, sizeof(value));
        rc_avpair_tostr(rh, service_vp, name, sizeof(name), value, sizeof(value));

        if (strcmp(name, "Cisco-AVPair")) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s=%s\n", uuid, name, value);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] %s\n", uuid, value);
        }

        if (strcmp("Cisco-Command-Code", name) == 0) {
            char new_name[256] = "";
            sprintf(new_name, "m2_route_%d", route);
            switch_channel_set_variable(channel, new_name, value);
            route++;
        } else if (strcmp("Cisco-AVPair", name) == 0 && strstr(value, "terminator=")) {
            char new_name[256] = "";
            sprintf(new_name, "m2_terminator_%d", terminator);
            switch_channel_set_variable(channel, new_name, strstr(value, "terminator=") + strlen("terminator="));
            terminator++;
        } else if (strcmp("Cisco-AVPair", name) == 0 && strstr(value, "=")) {

            char *ptr = NULL;
            char avp_name[256] = "";
            char tmp_avp_name[256] = "";
            char avp_value[256] = "";

            ptr = strstr(value, "=");
            strcpy(avp_value, ptr + 1);
            strncpy(tmp_avp_name, value, strlen(value) - strlen(ptr));
            sprintf(avp_name, "m2_%s", tmp_avp_name);

            if (strlen(avp_name) && strlen(avp_value)) {
                switch_channel_set_variable(channel, avp_name, avp_value);
            }

        } else {
            switch_channel_set_variable(channel, name, value);
        }
        service_vp = service_vp->next;
    }

    if (recv) {
        rc_avpair_free(recv);
        recv = NULL;
    }
    if (send) {
        rc_avpair_free(send);
        send = NULL;
    }
    if (rh) {
        rc_destroy(rh);
        rh = NULL;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Authentication request successfully sent to radius server\n", uuid);

    return;

    auth_err:

    if (result == 2) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Radius request rejected\n", uuid);

        // maybe we got m2_hangupcause code? if so, set it to channel variable
        service_vp = recv;
        while (service_vp != NULL) {
            rc_avpair_tostr(rh, service_vp, name, sizeof(name), value, sizeof(value));
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Got AVP %s = %s\n", uuid, name, value);
            if (strcmp("Cisco-AVPair", name) == 0 && strstr(value, "m2_hangupcause=")) {
                switch_channel_set_variable(channel, "m2_hangupcause", strstr(value, "m2_hangupcause=") + strlen("m2_hangupcause="));
            }
            service_vp = service_vp->next;
        }

    } else if (result == -2) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Bad response. Check if radius server is using the same shared secret as FreeSwitch\n", uuid);
    } else if (result == 1) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to send authentication request to radius server (reason: timeout)\n", uuid);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius %s] Failed to send authentication request to radius server (reason: general error)\n", uuid);
    }

    if (recv) {
        rc_avpair_free(recv);
        recv = NULL;
    }
    if (send) {
        rc_avpair_free(send);
        send = NULL;
    }
    if (rh) {
        rc_destroy(rh);
        rh = NULL;
    }

    // If authentication request failed (not due to rejection)
    // then send acct stop request to radius just in case there is a corresponding call waiting for further messages from
    if (result != 2) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Preparing to send delayed accounting stop request to radius!\n", uuid);
        sleep(5);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius %s] Sending now\n", uuid);
        m2_radius_send_acct_packet(0, 1, session, "", 500);
    }

}

SWITCH_STANDARD_APP(m2_radius_report_failed_handle) {

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Call failed, sending Accounting [stop] packet!\n");
    m2_radius_send_acct_packet(0, 1, session, "", 0);

}

SWITCH_STANDARD_API(m2_radius_reload) {

    stream->write_function(stream, "+OK\n");
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "Reloading devices\n");
    system("/usr/local/m2/m2_freeswitch_devices");
    return SWITCH_STATUS_SUCCESS;

}

SWITCH_STANDARD_API(m2_radius_recompile) {

    if (strcmp(cmd, "1") == 0) {
        if (m2_radius_load_config() != SWITCH_STATUS_SUCCESS) {
            stream->write_function(stream, "+ERR\n");
            return SWITCH_STATUS_TERM;
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Recompile is set to ON!\n");
            stream->write_function(stream, "Recompile is set to 'ON'\n");
            stream->write_function(stream, "+OK\n");
            use_secondary_connection = 1;
            return SWITCH_STATUS_SUCCESS;
        }
    } else if (strcmp(cmd, "0") == 0) {
        if (m2_radius_load_config() != SWITCH_STATUS_SUCCESS) {
            stream->write_function(stream, "+ERR\n");
            return SWITCH_STATUS_TERM;
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "[m2_radius] Recompile is set to OFF!\n");
            stream->write_function(stream, "Recompile is set to 'OFF'\n");
            stream->write_function(stream, "+OK\n");
            use_secondary_connection = 0;
            return SWITCH_STATUS_SUCCESS;
        }
    } else {
        stream->write_function(stream, "Unknown argument\n");
        stream->write_function(stream, "+ERR\n");
        return SWITCH_STATUS_TERM;
    }

}

SWITCH_STANDARD_API(m2_radius_show_version) {

    stream->write_function(stream, "+OK\n");
    stream->write_function(stream, "M2 Radius: %s\n", M2_VERSION);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "M2 Radius: %s\n", M2_VERSION);
    return SWITCH_STATUS_SUCCESS;

}

static const switch_state_handler_table_t state_handlers = {
    /*.on_init */ NULL,
    /*.on_routing */ NULL,
    /*.on_execute */ NULL,
    /*.on_hangup */ NULL,
    /*.on_exchange_media */ NULL,
    /*.on_soft_execute */ NULL,
    /*.on_consume_media */ NULL,
    /*.on_hibernate */ NULL,
    /*.on_reset */ NULL,
    /*.on_park */ NULL,
    /*.on_reporting */ m2_radius_accounting_stop
};


SWITCH_MODULE_LOAD_FUNCTION(mod_xml_m2_radius_load) {

    switch_application_interface_t *app_interface;
    switch_api_interface_t *mod_xml_m2_radius_api_interface;

    // connect my internal structure to the blank pointer passed to me
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    if (m2_radius_load_config() != SWITCH_STATUS_SUCCESS) {
        return SWITCH_STATUS_TERM;
    }

    switch_core_add_state_handler(&state_handlers);
    SWITCH_ADD_APP(app_interface, "m2_radius_auth", NULL, NULL, m2_radius_auth_handle, "m2_radius_auth", SAF_SUPPORT_NOMEDIA | SAF_ROUTING_EXEC);
    SWITCH_ADD_APP(app_interface, "m2_radius_report_failed", NULL, NULL, m2_radius_report_failed_handle, "m2_radius_report_failed", SAF_SUPPORT_NOMEDIA | SAF_ROUTING_EXEC);

    SWITCH_ADD_API(mod_xml_m2_radius_api_interface, "m2_recompile", "m2_radius handle recompile", m2_radius_recompile, "");
    SWITCH_ADD_API(mod_xml_m2_radius_api_interface, "m2_reload", "m2_radius reload device", m2_radius_reload, "");
    SWITCH_ADD_API(mod_xml_m2_radius_api_interface, "m2_show_status", "m2_radius show version", m2_radius_show_version, "");

    if (switch_event_bind(modname, SWITCH_EVENT_CHANNEL_ANSWER, SWITCH_EVENT_SUBCLASS_ANY, m2_radius_accounting_start, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Couldn't bind M2 answer event!\n");
        return SWITCH_STATUS_GENERR;
    }

    if (switch_event_bind(modname, SWITCH_EVENT_RELOADXML, SWITCH_EVENT_SUBCLASS_ANY, m2_xml_radius_reload_event, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[m2_radius] Couldn't bind M2 reload event!\n");
        return SWITCH_STATUS_GENERR;
    }

    // indicate that the module should continue to be loaded
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xml_m2_radius_shutdown) {

    switch_core_remove_state_handler(&state_handlers);

    if (config.m2_radius_auth_conf) {
        switch_xml_free(config.m2_radius_auth_conf);
    }

    if (config.m2_radius_acct_start_conf) {
        switch_xml_free(config.m2_radius_acct_start_conf);
    }

    if (config.m2_radius_acct_stop_conf) {
        switch_xml_free(config.m2_radius_acct_stop_conf);
    }

    return SWITCH_STATUS_SUCCESS;

}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
