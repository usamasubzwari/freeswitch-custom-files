/*
    List of STANDARD (M2_STANDARD_AVP) radius attribute-value pairs used by M2 core"
        User-Name
        Calling-Station-Id
        Called-Station-Id
        call-id
        Acct-Session-Time
        h323-disconnect-cause
        h323-setup-time
        h323-connect-time
        h323-disconnect-time
        h323-remote-address

    Custom radius attribute-value pairs (M2_CISCO_AVP) usually start with freeswitch-xxxx=yyyyy:
        Cisco-AVPair=freeswitch-callerid-name=xxxxx
        Cisco-AVPair=freeswitch-src-channel=yyyyy
        Cisco-AVPair=freeswitch-server-id=zzzzz
        ....

    One exception is call-id - it can be both in standard format and in custom format:
        call-id=xxxxxxxxxxx
        Cisco-AVPair=call-id=xxxxxxxxx
*/


/*
    Add attribute value pair to radius response
*/


static void m2_radius_add_attribute_value_pair_tp(calldata_t *cd, char *attribute, char *value, int attr_type, int tp_id)
{
    char tp_attribute[256] = "";

    sprintf(tp_attribute, "%s_tp_%d", attribute, tp_id);
    m2_radius_add_attribute_value_pair(cd, tp_attribute, value, attr_type);
}

static void m2_radius_add_attribute_value_pair(calldata_t *cd, char *attribute, char *value, int attr_type)
{
    char attribute_name[256] = "";
    char attribute_value[256] = "";

    if (attr_type == M2_CISCO_AVP) {
        sprintf(attribute_value, "%s=%s", attribute, value);
        sprintf(attribute_name, "Cisco-AVPair");
    } else if (attr_type == M2_STANDARD_AVP) {
        strcpy(attribute_name, attribute);
        strcpy(attribute_value, value);
    } else {
        return;
    }

#ifdef FREERADIUS3
    REQUEST *request = cd->radius_auth_request;
    pair_make_reply(attribute_name, attribute_value, T_OP_EQ);
#else
    VALUE_PAIR *vp = NULL;
    vp = pairmake(attribute_name, attribute_value, T_OP_SET);
    pairadd(&cd->radius_auth_request->reply->vps, vp);
#endif
}


/*
    Get value from radius attribute-value pair by name
*/


static void m2_radius_get_attribute_value_by_name(REQUEST *request, char *attribute, char *value, long unsigned int len, int attr_type)
{
    if (!request) return;

    VALUE_PAIR *item_vp;
    item_vp = request->packet->vps;

    // Parse packet and look for specified attribute
    while (item_vp != NULL) {

#ifdef FREERADIUS3
        if (attr_type == M2_STANDARD_AVP) {
            if (strcmp(item_vp->da->name, attribute) == 0) {
                if (item_vp->da->type == PW_TYPE_STRING && item_vp->vp_strvalue) {
                    strlcpy(value, item_vp->vp_strvalue, len);
                } else if (item_vp->da->type == PW_TYPE_INTEGER) {
                    sprintf(value, "%d", item_vp->vp_integer);
                }
                break;
            }
        } else if (attr_type == M2_CISCO_AVP) {
            if (strcmp(item_vp->da->name, "Cisco-AVPair") == 0) {
                if (strstr(item_vp->vp_strvalue, attribute)) {
                    strlcpy(value, item_vp->vp_strvalue + strlen(attribute) + 1, len);
                    break;
                }
            }
        }
#else
        if (attr_type == M2_STANDARD_AVP) {
            if (strcmp(item_vp->name, attribute) == 0) {
                strlcpy(value, item_vp->vp_strvalue, len);
                break;
            }
        } else if (attr_type == M2_CISCO_AVP) {
            if (strcmp(item_vp->name, "Cisco-AVPair") == 0) {
                if (strstr(item_vp->vp_strvalue, attribute)) {
                    strlcpy(value, item_vp->vp_strvalue + strlen(attribute) + 1, len);
                    break;
                }
            }
        }
#endif

        item_vp = item_vp->next;
    }
}


/*
    Get accounting type (either START or STOP)
*/


static int m2_radius_get_accounting_type(REQUEST *request)
{
    char status_type[100] = "";

    m2_radius_get_attribute_value_by_name(request, "Acct-Status-Type", status_type, sizeof(status_type), M2_STANDARD_AVP);

    if (strcmp(status_type, "Start") == 0 || strcmp(status_type, "1") == 0) {
        return 1;
    } else if (strcmp(status_type, "Stop") == 0 || strcmp(status_type, "2") == 0) {
        return 2;
    }

    return 0;
}


/*
    skip SUCCESS(0) requests
    i'm not sure why this happens but it ruins billing
    this is just a quickfix and should be fixed properly in the future
    related to CRM #31653

    also this check is used to find special cases when bypass media is enabled and provider sends early media and then rejects call
    in this case core should skip other routes because LUA exists on situations like this and will not do any routing to other routes
*/


static int m2_radius_check_request(calldata_t *cd, REQUEST *radius_acctstop_request)
{
    if (!radius_acctstop_request) {
        return 0;
    }

    char freeswitch_cause[128] = "";
    char freeswitch_hgc_string[128] = "";
    char freeswitch_bypass_early_media_string[128] = "";
    int freeswitch_hgc_integer = 0;
    int freeswitch_bypass_early_media = 0;

    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "h323-disconnect-cause", freeswitch_cause, sizeof(freeswitch_cause), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-hangupcause", freeswitch_hgc_string, sizeof(freeswitch_hgc_string), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-bypass-early-media", freeswitch_bypass_early_media_string, sizeof(freeswitch_bypass_early_media_string), M2_CISCO_AVP);

    if (strlen(freeswitch_hgc_string)) {
       freeswitch_hgc_integer = atoi(freeswitch_hgc_string);
    }

    if (strlen(freeswitch_bypass_early_media_string)) {
       freeswitch_bypass_early_media = atoi(freeswitch_bypass_early_media_string);
    }

    if (freeswitch_bypass_early_media) {
        cd->bypass_early_media = 1;
    }

    if (strcmp(freeswitch_cause, "SUCCESS") == 0 && freeswitch_hgc_integer == 0) {
        return 1;
    }

    return 0;
}


/*
    Add radius auth type M2
*/


static void m2_radius_add_auth_type(REQUEST *request)
{
#ifdef FREERADIUS3
    pair_make_config("Auth-Type", "M2", T_OP_EQ);
#else
    pairadd(&request->config_items, pairmake("Auth-Type", "M2", T_OP_EQ));
#endif
}
