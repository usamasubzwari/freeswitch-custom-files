
static int m2_authorization(calldata_t *cd) {

    m2_log(M2_NOTICE, "----------------------------------- AUTHORIZATION ------------------------------------\n");

    // check if user_is blocked
    if (cd->op->user_blocked) {
        m2_log(M2_WARNING, "User is blocked! id[%d%s]\n", cd->op->user_id, cd->op->user_name);
        m2_set_hangupcause(cd, 311);
        // saving into cache
        m2_hgc_cache_set(cd, 311, CACHE_TTL_HGC311);
        return 1;
    }

    // check if codecs are allowed
    if (strlen(cd->op->codec_list) && strlen(cd->op->allowed_codecs) && cd->op->codecs_are_allowed == 0) {
        m2_log(M2_WARNING, "OP codecs [%s] are not allowed! Allowed codecs [%s]\n", cd->op->codec_list, cd->op->allowed_codecs);
        m2_set_hangupcause(cd, 318);
        return 1;
    }

    // check if call limit is not reached
    int ac_count = active_calls_count;
    if (ac_count > CALL_LIMIT) {
        m2_log(M2_WARNING, "M2 can not make more calls (active calls/limit: %d/%d)\n", ac_count, CALL_LIMIT);
        m2_set_hangupcause(cd, 302);
        // saving into cache
        m2_hgc_cache_set(cd, 302, CACHE_TTL_HGC302);
        return 1;
    }

    // assign user to this call
    cd->user = m2_find_user(cd->op->user_id);

    if (!cd->user) {
        m2_log(M2_ERROR, "User not found\n");
        m2_set_hangupcause(cd, 0);
        return 1;
    }

    m2_log(M2_DEBUG, "User balance: %.5f\n", cd->user->balance);

    if (!cd->user) {
        m2_log(M2_WARNING, "Could not assign user to this call!\n");
        m2_set_hangupcause(cd, 0);
        return 1;
    }

    // mark call attempt
    m2_set_active_call(cd);

    // for some reason didn't get active call id? Reject call
    if (!cd->active_call_id) {
        m2_log(M2_WARNING, "M2 can not make more calls (active calls/limit: %d/%d)\n", ac_count, CALL_LIMIT);
        m2_set_hangupcause(cd, 302);
        // saving into cache
        m2_hgc_cache_set(cd, 302, CACHE_TTL_HGC302);
        return 1;
    }

    // check blacklisting/whitelisting for src number
    if (strcmp(cd->op->enable_static_src_list, "blacklist") == 0 || strcmp(cd->op->enable_static_src_list, "whitelist") == 0) {
        m2_log(M2_NOTICE, "Checking static [%s] for src number [%s]\n", cd->op->enable_static_src_list, cd->src);
        int static_blacklist_status = m2_check_static_blacklist(cd, cd->op->static_src_list_id, cd->op->enable_static_src_list, cd->src);
        // blacklisted
        if (static_blacklist_status == 1) {
            m2_set_hangupcause(cd, 334);
            return 1;
        }
        // not in whitelist
        if (static_blacklist_status == -1) {
            m2_set_hangupcause(cd, 335);
            return 1;
        }
    }

    // check blacklisting/whitelisting for dst number
    if (strcmp(cd->op->enable_static_list, "blacklist") == 0 || strcmp(cd->op->enable_static_list, "whitelist") == 0) {
        m2_log(M2_NOTICE, "Checking static [%s] for dst [%s]\n", cd->op->enable_static_list, cd->dst);
        int static_blacklist_status = m2_check_static_blacklist(cd, cd->op->static_list_id, cd->op->enable_static_list, cd->dst);
        // blacklisted
        if (static_blacklist_status == 1) {
            m2_set_hangupcause(cd, 325);
            return 1;
        }
        // not in whitelist
        if (static_blacklist_status == -1) {
            m2_set_hangupcause(cd, 326);
            return 1;
        }
    }

    // check concurrent calls for user
    if (cd->op->user_call_limit > 0) {
        m2_log(M2_DEBUG, "Checking active calls for user\n");
        int user_active_calls = cd->user->in_active_calls;
        if (user_active_calls > cd->op->user_call_limit) {
            m2_log(M2_WARNING, "User's [%d%s] concurrent call limit reached (active users's calls/limit: %d/%d)\n", cd->op->user_id, cd->op->user_name, user_active_calls, cd->op->user_call_limit);
            m2_set_hangupcause(cd, 313);
            // saving into cache
            m2_hgc_cache_set(cd, 313, CACHE_TTL_HGC313);
            return 1;
        }
        m2_log(M2_NOTICE, "Active calls for user %d, call limit: %d\n", user_active_calls, cd->op->user_call_limit);
    }

    // check concurrent calls for OP
    if (cd->op->capacity > 0) {
        m2_log(M2_DEBUG, "Checking active calls for OP\n");
        int originator_current_active_calls = connp_index[cd->op->id].in_active_calls;
        if (originator_current_active_calls > cd->op->capacity) {
            m2_log(M2_WARNING, "OP reached capacity limit (active calls/capacity: %d/%d)\n", originator_current_active_calls, cd->op->capacity);
            m2_set_hangupcause(cd, 303);
            // saving into cache
            m2_hgc_cache_set(cd, 303, CACHE_TTL_HGC303);
            return 1;
        }
        m2_log(M2_NOTICE, "Active calls for OP: %d, capacity: %d\n", originator_current_active_calls, cd->op->capacity);
    }

    // check cps limitations (how many calls per period can pass)
    if (m2_check_cps(cd->op->id, cd)) {
        m2_set_hangupcause(cd, 304);
        // saving into cache
        m2_hgc_cache_set(cd, 304, CACHE_TTL_HGC304);
        return 1;
    }

    // check if src regex matches
    if (!cd->op->src_regexp_status) {
        m2_set_hangupcause(cd, 305);
        m2_log(M2_WARNING, "Source number is not allowed to dial through this OP. Src: %s, OP src regexp: %s\n", cd->src, cd->op->src_regexp);
        return 1;
    }

    // check if src regex is not denied
    if (cd->op->src_deny_regexp_status) {
        m2_log(M2_WARNING, "Source number is not allowed to dial through this OP. Src: %s, OP src deny regexp: %s\n", cd->src, cd->op->src_deny_regexp);
        m2_set_hangupcause(cd, 305);
        return 1;
    }

    // check customer balance
    if (cd->op->user_balance <= cd->op->user_balance_limit) {
        m2_log(M2_WARNING, "User's [%d%s] balance limit reached! balance: %.5f, limit: %.5f\n", cd->op->user_id, cd->op->user_name, cd->op->user_balance, cd->op->user_balance_limit);
        m2_set_hangupcause(cd, 306);
        // saving into cache
        m2_hgc_cache_set(cd, 306, CACHE_TTL_HGC306);
        return 1;
    }

    // get op ratedetails
    int destination_blocked = m2_get_ratedetails(cd);
    if (destination_blocked) {
        if (destination_blocked == -1) {
            m2_set_hangupcause(cd, 330);
        } else {
            m2_log(M2_WARNING, "Rates not found for OP id[%d%s], dst: %s, prefix: %s\n", cd->op->id, cd->op->description, cd->dst, cd->op->prefix);
            m2_set_hangupcause(cd, 307);
        }
        return 1;
    }

    if (cd->op->user_max_call_rate > 0 && (cd->op_rate_after_exchange > cd->op->user_max_call_rate)) {
        m2_log(M2_WARNING, "User's call rate [%.3f] is higher than allowed [%.3f]\n", cd->op_rate_after_exchange, cd->op->user_max_call_rate);
        m2_set_hangupcause(cd, 340);
        return 1;
    }

    double active_calls_price = cd->user->total_price;

    m2_log(M2_NOTICE, "User's total call price for all current active calls: %.5f, balance after adjustment: %.5f\n", active_calls_price, cd->op->user_balance - active_calls_price);

    // handle too high values (we don't want overflow when doing mathematical operations)
    if (cd->op->user_balance_limit < -100000000) {
        m2_log(M2_NOTICE, "Balance min [%f] is too low! Value will be set to -100000000\n", cd->op->user_balance_limit);
        cd->op->user_balance_limit = -100000000;
    }

    // handle too low values (we don't want overflow when doing mathematical operations)
    if (cd->op_rate > 0 && cd->op_rate < 0.000001) {
        m2_log(M2_NOTICE, "OP rate [%f] is too low! Value will be set to 0.000001\n", cd->op_rate);
        cd->op_rate = 0.000001;
    }

    // calculate timeout
    if (cd->op_rate != 0) {
        cd->timeout = floorf((cd->op->user_balance - active_calls_price - cd->op->user_balance_limit) / (cd->op_rate / cd->op_exchange_rate) * 60);
    } else {
        cd->timeout = global_call_timeout;
    }

    if (cd->op->max_timeout) {
        if (cd->op->max_timeout < cd->timeout) {
            m2_log(M2_NOTICE, "Timeout after OP max call timeout: %d\n", cd->op->max_timeout);
            cd->timeout = cd->op->max_timeout;
        }
    }

    if (cd->timeout < 0) {
        cd->timeout = 0;
    }
    if (cd->timeout > global_call_timeout) {
        cd->timeout = global_call_timeout;
    }

    m2_log(M2_NOTICE, "OP timeout: %lld\n", cd->timeout);

    // check increment
    if (!cd->op_increment) cd->op_increment = 1;
    if (cd->op_increment != 1) {
        cd->timeout = (cd->timeout / cd->op_increment) * cd->op_increment;
        m2_log(M2_NOTICE, "Timeout after increment [%i] adjustment: %lli\n", cd->op_increment, cd->timeout);
    }

    // check minimal time
    if (cd->op_min_time > 0 && cd->timeout > 0) {
        if (cd->timeout < cd->op_min_time) {
            cd->timeout = 0;
        }
        m2_log(M2_NOTICE, "Timeout after minimal time [%i] adjustment: %lli\n", cd->op_min_time, cd->timeout);
    }

    if (cd->timeout <= 1) {
        m2_log(M2_WARNING, "User [%d%s] balance too low to make a call. \n", cd->op->user_id, cd->op->user_name);
        m2_set_hangupcause(cd, 320);
        // saving into cache
        m2_hgc_cache_set(cd, 320, CACHE_TTL_HGC320);
        return 1;
    }


    // Get DPeers from OP trie
    int dp_from_trie_res = 0;
    if (dptp_trie_on) {
        dp_from_trie_res = m2_trie_get_dps(cd);
    }

    // get dialpeers from DB (if no DPs from Trie received)
    if (dp_from_trie_res > 0 || !dptp_trie_on) {
        m2_log(M2_DEBUG, "---------\nLooking for DPs in DB\n");
        m2_get_dial_peers(cd, 0);
        meter.trie_dp_not_found++;
    } else {
        meter.trie_dp_found++;
    }


    // saving DPeers to OP Trie from DB
    //if (dptp_trie_on && !dp_from_trie && cd->dpeers_count) m2_trie_save_dps(cd);
    if (dptp_trie_on && dp_from_trie_res > 0) m2_trie_save_dps(cd);



    // check if failover is skipped in main RG
    if (cd->skip_failover_routing_group) {
        m2_log(M2_NOTICE, "Skip Failover Routing Group option is enabled\n");
        cd->op->failover_1_routing_group_id = 0;
        cd->op->failover_2_routing_group_id = 0;
    }

    if (cd->op->failover_1_routing_group_id) {
        m2_get_dial_peers(cd, 1);
    }

    // check if failover is skipped in failover RG
    if (cd->op->failover_1_routing_group_id && cd->skip_failover_routing_group) {
        m2_log(M2_NOTICE, "Skip Failover Routing Group option is enabled\n");
        cd->op->failover_2_routing_group_id = 0;
    }

    if (cd->op->failover_2_routing_group_id) {
        m2_get_dial_peers(cd, 2);
    }

    // can't go to routing, because no valid dial peer was found
    if (!cd->dpeers_count && !cd->failover_1_dpeers_count && !cd->failover_2_dpeers_count) {
        if (cd->op->failover_1_routing_group_id || cd->op->failover_2_routing_group_id) {
            m2_log(M2_WARNING, "No valid DP found. User [%d%s]\n", cd->op->user_id, cd->op->user_name);
        }
        m2_set_hangupcause(cd, 308);
        return 1;
    }


    meter.m2_tprate_count_start++;
    double start_time = m2_get_current_time();

    int tp_from_trie_res = 1;

    if (cd->dpeers_count) {

        // get TP with ratedetails from Trie/Cache
        if (dptp_trie_on) {
            tp_from_trie_res = m2_tp_activate_from_trie_cache(cd);
        }

        if (tp_from_trie_res == 1) {

            meter.trie_tp_not_found++;

            m2_log(M2_WARNING, "Searching for TPs in DB\n");   // we REALLY don't want this
            m2_get_tp_ratedetails(cd, 0);
            m2_log(M2_NOTICE, "Found [%d] suitable TP(s)\n", cd->tp_count);

        } else {
            meter.trie_tp_found++;
        }

    } else {
        m2_log(M2_WARNING, "DPs not found in Routing Group [%d]\n", cd->op->routing_group_id);
    }

    if (cd->op->failover_1_routing_group_id && cd->failover_1_dpeers_count) {
        m2_log(M2_NOTICE, "Searching for TPs in failover #1 DPs\n");
        m2_get_tp_ratedetails(cd, 1);
        m2_log(M2_NOTICE, "Found %d suitable failover #1 TPs\n", cd->failover_1_tp_count);
    } else {
        // disable failover, because we did not found any dial peer for this failover routing group
        cd->op->failover_1_routing_group_id = 0;
    }

    if (cd->op->failover_2_routing_group_id && cd->failover_2_dpeers_count) {
        m2_log(M2_NOTICE, "Searching for TPs in failover #2 DPs\n");
        m2_get_tp_ratedetails(cd, 2);
        m2_log(M2_NOTICE, "Found %d suitable failover #2 terminators\n", cd->failover_2_tp_count);
    } else {
        // disable failover, because we did not found any dial peer for this failover routing group
        cd->op->failover_2_routing_group_id = 0;
    }


    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_tprate_time += run_time;
    meter.m2_tprate_count++;
    if (run_time > meter.m2_tprate_time_max) {
        meter.m2_tprate_time_max = run_time;
    }
    if (run_time > meter.m2_tprate_time_maxps) {
        meter.m2_tprate_time_maxps = run_time;
    }



    if (cd->tp_count) {
        m2_show_tp(cd, 0);
    }

    if (cd->failover_1_tp_count) {
        m2_show_tp(cd, 1);
    } else {
        // disable failover, because we did not found any terminators in failover dial peer
        cd->op->failover_1_routing_group_id = 0;
    }

    if (cd->failover_2_tp_count) {
        m2_show_tp(cd, 2);
    } else {
        // disable failover, because we did not found any terminators in failover dial peer
        cd->op->failover_2_routing_group_id = 0;
    }

    // check if we have at least one terminator
    if (!cd->tp_count && !cd->failover_1_tp_count && !cd->failover_2_tp_count) {
        m2_log(M2_WARNING, "Suitable TP not found. User [%d%s] OP [%d%s] dst [%s]\n", cd->op->user_id, cd->op->user_name, cd->op->id, cd->op->description, cd->dst);
        if (cd->last_tp_hangupcause) {
            m2_set_hangupcause(cd, cd->last_tp_hangupcause);
        } else {
            m2_set_hangupcause(cd, 310);
        }
        return 1;
    }

    if (cd->radius_auth_request) {
        // timeout
        char timeout_string_value[100] = "";
        sprintf(timeout_string_value, "%lld", cd->timeout);
        m2_radius_add_attribute_value_pair(cd, "h323-credit-time", timeout_string_value, M2_STANDARD_AVP);

        // codecs
        if (strlen(cd->op->allowed_codecs)) {
            m2_radius_add_attribute_value_pair(cd, "codecs", cd->op->allowed_codecs, M2_CISCO_AVP);
        }

        // hgc mapping
        if (strlen(cd->op->hgc_mapping)) {
            m2_radius_add_attribute_value_pair(cd, "hgc_mapping", cd->op->hgc_mapping, M2_CISCO_AVP);
        }

        // reroute stop hgc
        if (strlen(reroute_stop_hgc)) {
            char reroute_stop_hgc_value[256] = "";
            sprintf(reroute_stop_hgc_value, ",%s,", reroute_stop_hgc);
            m2_radius_add_attribute_value_pair(cd, "reroute_stop_hgc", reroute_stop_hgc_value, M2_CISCO_AVP);
        }

        // disable q850 reason header
        if (cd->op->disable_q850) {
            m2_radius_add_attribute_value_pair(cd, "disable_q850", "1", M2_CISCO_AVP);
        }

        if (!cd->op->forward_rpid) {
            m2_radius_add_attribute_value_pair(cd, "forward_rpid", "0", M2_CISCO_AVP);
        }

        // custom sip header
        if (strlen(cd->op->custom_sip_header)) {
            char custom_sip_header_fs[256] = "";
            char *custom_sip_header_fs_ptr = NULL;

            strlcpy(custom_sip_header_fs, cd->op->custom_sip_header, sizeof(custom_sip_header_fs));
            custom_sip_header_fs_ptr = strstr(custom_sip_header_fs, ":");

            if (custom_sip_header_fs_ptr) {
                *custom_sip_header_fs_ptr = '=';
            }

            m2_radius_add_attribute_value_pair(cd, "custom_sip_header", custom_sip_header_fs, M2_CISCO_AVP);
        }

        if (cd->op->bypass_media) {
            m2_radius_add_attribute_value_pair(cd, "bypass_media", "1", M2_CISCO_AVP);
        }

        if (cd->op->inherit_codec) {
            m2_radius_add_attribute_value_pair(cd, "inherit_codec", "1", M2_CISCO_AVP);
        }

        if (cd->op->ring_instead_progress) {
            m2_radius_add_attribute_value_pair(cd, "ring_instead_progress", "1", M2_CISCO_AVP);
        }

        if (cd->op->set_sip_contact) {
            m2_radius_add_attribute_value_pair(cd, "set_sip_contact", "1", M2_CISCO_AVP);
        }

        if (cd->op->change_rpidpai_host) {
            m2_radius_add_attribute_value_pair(cd, "change_rpidpai_host", "1", M2_CISCO_AVP);
        }

        if (cd->op->ignore_183nosdp) {
            m2_radius_add_attribute_value_pair(cd, "ignore_183nosdp", "1", M2_CISCO_AVP);
        }

        if (cd->op->fake_ring) {
            m2_radius_add_attribute_value_pair(cd, "fake_ring", "1", M2_CISCO_AVP);
        }
    } else {
        m2_log(M2_ERROR, "Cannot add info to radius auth packet. Cd->radius_auth_request is null. Report it to developers!\n");
    }

    // set flag that this call should be updated
    cd->active_call_update = 1;

    m2_change_callstate(cd, M2_ROUTING_STATE);

    return 0;
}


static int m2_authorization_wrapper(calldata_t *cd) {

    meter.m2_author_count_start++;
    double start_time = m2_get_current_time();

    int res = m2_authorization(cd);

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_author_time += run_time;
    meter.m2_author_count++;
    if (run_time > meter.m2_author_time_max) {
        meter.m2_author_time_max = run_time;
    }
    if (run_time > meter.m2_author_time_maxps) {
        meter.m2_author_time_maxps = run_time;
    }

    return res;

}



static int m2_get_ratedetails_main(calldata_t *cd) {


    MYSQL_RES *result = NULL;
    MYSQL_ROW row;
    int connection = 0;

    char query[10000] = "";
    char prefix_sql_line[9000] = "";
    int got_rates = 0;
    int tariff_id = 0;
    int blocked_rate = 0;
    char tariff_cond[256] = "";
    char tariff_name[100] = "";
    char tariff_name_sql[100] = "''";

    // trie vars
    char   prefix[1024] = "";
    double rate = 0;
    double connection_fee = 0;
    int    increment = 0, min_time = 0, blocked = 0;

    int rate_from_trie = 0;

    // do not use trie cache if match or custom tariffs are present - not implemented yet (usual values: match 0, default -1)
    // also do not use for us jurisdictional routing
    if (cd->op->match_tariff_id < 1 && cd->op->custom_tariff_id < 1 && cd->op->us_jurisdictional_routing == 0) {

        // do we have an OP Trie? Create if not
        if (connp_index[cd->op->id].op_tariff_trie == NULL) {
            connp_index[cd->op->id].op_tariff_trie = m2_trie_init(connp_index[cd->op->id].op_tariff_id);
        }

        // checking trie
        if (!m2_trie_get_prefix(cd, connp_index[cd->op->id].op_tariff_trie, cd->dst, prefix, &rate, &connection_fee, &increment, &min_time, &blocked)) {
            m2_log(M2_DEBUG, "Ratedetails (from Trie) for OP: prfx[%s] rate[%f] c.fee[%f] inc[%i] mintime[%i] blocked[%i]", prefix, rate, connection_fee, increment, min_time, blocked);
            rate_from_trie = 1;
            meter.trie_op_found++;

            // assigning values from the trie
            strcpy(cd->op->prefix, prefix);
            cd->op_rate = rate;
            cd->op_connection_fee = connection_fee;
            cd->op_increment = increment;
            cd->op_min_time = min_time;
            cd->op_exchange_rate = connp_index[cd->op->id].op_tariff_trie->exchange_rate;
            strcpy(cd->op_currency, connp_index[cd->op->id].op_tariff_trie->currency);
            tariff_id = connp_index[cd->op->id].op_tariff_trie->tariff_id;
            blocked_rate = blocked;

            if (cd->op_exchange_rate == 0) cd->op_exchange_rate = 1;
            cd->op_rate_after_exchange = cd->op_rate / cd->op_exchange_rate;
            got_rates = 1;

        } else {
            m2_log(M2_DEBUG, "TRIE OP [%s] no prefix found", cd->dst);
            meter.trie_op_not_found++;
        }

    }


    if (!rate_from_trie) {

        if (cd->op->match_tariff_id && m2_check_rule_sets(cd)) {
            // we have additional tariff which will be applied if src/dst will match rule-sets
            sprintf(tariff_cond, "= %d", cd->op->match_tariff_id);
        } else {
            // usual case with tariff_id and custom_tariff_id
            sprintf(tariff_cond, "IN (%d, %d)", cd->op->tariff_id, cd->op->custom_tariff_id);
        }

        if (show_entity_names) {
            strcpy(tariff_name_sql, "tariffs.name");
        }

        meter.m2_oprate_sql_count_start++;
        double start_time = m2_get_current_time();


        // split dst into parts
        m2_format_prefix_sql(prefix_sql_line, cd->dst);

        sprintf(query, "SELECT rates.prefix, ratedetails.rate, ratedetails.connection_fee, ratedetails.increment_s, ratedetails.min_time, "
            "currencies.exchange_rate, currencies.name, rates.effective_from, IF(tariffs.id = %d, 1, 0) AS custom_tariff, tariffs.id, %s, ratedetails.blocked FROM rates "
            "JOIN tariffs ON tariffs.id = rates.tariff_id "
            "LEFT JOIN currencies ON currencies.name = tariffs.currency "
            "JOIN ratedetails ON (ratedetails.rate_id = rates.id AND (ratedetails.daytype = '%s' OR ratedetails.daytype = '') "
            "AND '%s' BETWEEN ratedetails.start_time AND ratedetails.end_time) "
            "WHERE rates.tariff_id %s AND "
            "rates.prefix IN (%s) AND "
            "(rates.effective_from < NOW() OR "
            "rates.effective_from IS NULL) "
            "ORDER BY LENGTH(rates.prefix) DESC, custom_tariff DESC, rates.effective_from DESC "
            "LIMIT 1", cd->op->custom_tariff_id, tariff_name_sql, cd->op->user_daytype, cd->op->user_time, tariff_cond, prefix_sql_line);

        if (m2_mysql_query(cd, query, &connection)) {
            return 1;
        }

        // query succeeded, get results and mark connection as available
        result = mysql_store_result(&mysql[connection]);
        mysql_connections[connection] = 0;

        if (result) {

            while ((row = mysql_fetch_row(result))) {

                if (row[0]) strlcpy(cd->op->prefix, row[0], sizeof(cd->op->prefix)); else strlcpy(cd->op->prefix, "", sizeof(cd->op->prefix));
                m2_filter_string_strict(cd->op->prefix);   // to be sure prefix will not come from db messed up
                if (row[1]) cd->op_rate = atof(row[1]); else cd->op_rate = 0;
                if (row[2]) cd->op_connection_fee = atof(row[2]); else cd->op_connection_fee = 0;
                if (row[3]) cd->op_increment = atoi(row[3]); else cd->op_increment = 1;
                if (row[4]) cd->op_min_time = atoi(row[4]); else cd->op_min_time = 0;
                if (row[5]) cd->op_exchange_rate = atof(row[5]); else cd->op_exchange_rate = 1;
                if (row[6]) strlcpy(cd->op_currency, row[6], sizeof(cd->op_currency)); else strlcpy(cd->op_currency, "", sizeof(cd->op_currency));
                if (row[7]) strlcpy(cd->op_rate_effective_from, row[7], sizeof(cd->op_rate_effective_from)); else strlcpy(cd->op_rate_effective_from, "null", sizeof(cd->op_rate_effective_from));
                // row[8] custom tariff
                if (row[9]) tariff_id = atoi(row[9]); else tariff_id = 0;
                if (row[10] && strlen(row[10])) sprintf(tariff_name, ":%s", row[10]); else  strcpy(tariff_name, "");
                if (row[11]) blocked_rate = atoi(row[11]); else blocked_rate = 0;

                if (cd->op_exchange_rate == 0) {
                    cd->op_exchange_rate = 1;
                }

                cd->op_rate_after_exchange = cd->op_rate / cd->op_exchange_rate;

                // check if we got all the data from ratedetails
                if (row[0] && row[1] && row[2] && row[3] && row[4]) {
                    got_rates = 1;
                }

            }

            mysql_free_result(result);

        }


        // saving metering stats
        double run_time = m2_get_current_time() - start_time;
        meter.m2_oprate_sql_time += run_time;
        meter.m2_oprate_sql_count++;
        if (run_time > meter.m2_oprate_sql_time_max) {
            meter.m2_oprate_sql_time_max = run_time;
        }
        if (run_time > meter.m2_oprate_sql_time_maxps) {
            meter.m2_oprate_sql_time_maxps = run_time;
        }

    } // if (!rate_from_trie)


    // show rates if found
    if (!got_rates) {
        return 1;
    } else {
        if (!rate_from_trie) {
            m2_log(M2_NOTICE, "Ratedetails (from DB) for OP: prefix: %s, rate: %.5f, connection_fee: %.5f, "
                "increment: %d, min_time: %d, exchange_rate: %.5f, currency: %s, rate in default currency: %.5f, effective_from: %s, tariff: [%d%s], "
                "blocked_rate: %d\n",
                cd->op->prefix, cd->op_rate, cd->op_connection_fee, cd->op_increment, cd->op_min_time, cd->op_exchange_rate, cd->op_currency,
                cd->op_rate_after_exchange, cd->op_rate_effective_from, tariff_id, tariff_name, blocked_rate);
        }
    }


    if (cd->op->match_tariff_id < 1 && cd->op->custom_tariff_id < 1) {

        // saving to cache
        if (!rate_from_trie && connp_index[cd->op->id].op_tariff_trie != NULL){
            pthread_mutex_lock(&connp_index[cd->op->id].op_tariff_trie->lock);
            m2_trie_add_prefix(connp_index[cd->op->id].op_tariff_trie, cd->op->prefix, 1, cd->op_rate, cd->op_connection_fee, cd->op_increment, cd->op_min_time, blocked_rate, 1, 0);
            pthread_mutex_unlock(&connp_index[cd->op->id].op_tariff_trie->lock);
            m2_log(M2_DEBUG, "TRIE OP Rate [%f] for prefix [%s] saved to trie.\n", cd->op_rate, cd->op->prefix);
        }

    }


    if (cd->op_rate == -1 || blocked_rate == 1) {
        if (cd->op_rate == -1){
            m2_log(M2_WARNING, "User's rate is -1. Destination is blocked!\n");
        } else {
            m2_log(M2_WARNING, "Destination is blocked!\n");
        }
        return -1;
    }

    return 0;

}


// wrapper for metering
static int m2_get_ratedetails(calldata_t *cd) {

    meter.m2_oprate_count_start++;
    double start_time = m2_get_current_time();

    int res = m2_get_ratedetails_main(cd);

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_oprate_time += run_time;
    meter.m2_oprate_count++;
    if (run_time > meter.m2_oprate_time_max) {
        meter.m2_oprate_time_max = run_time;
    }
    if (run_time > meter.m2_oprate_time_maxps) {
        meter.m2_oprate_time_maxps = run_time;
    }

    return res;

}



/*
    Get data for terminators
*/


static int m2_get_tp_ratedetails(calldata_t *cd, int failover) {

    MYSQL_RES *result = NULL;
    MYSQL_ROW row;
    int connection = 0;
    char query[10000] = "";
    char prefix_sql_line[9000] = "";
    char dpeer_id_list[1024] = "";
    char order_sql_string[256] = "tpw ASC";
    char skip_zero_percent[64] = "";
    int i = 0;
    int routing_group_id = 0;
    int terminator_cps_array[50] = { 0 };
    int terminator_cps_count = 0;
    int check_terminator_cps = 1;
    char tp_description_sql[30] = "''";

    if (show_entity_names) {
        strcpy(tp_description_sql, "devices.description");
    }

    if (strcmp(cd->op->routing_algorithm, "lcr") == 0) {
        strlcpy(order_sql_string, "D.rate / D.exchange_rate ASC", sizeof(order_sql_string));
    }

    if (strcmp(cd->op->routing_algorithm, "percent") == 0) {
        strlcpy(order_sql_string, "D.tpp DESC", sizeof(order_sql_string));
        strlcpy(skip_zero_percent, " AND dpeer_tpoints.tp_percent > 0 ", sizeof(skip_zero_percent));
    }

    if (strcmp(cd->op->routing_algorithm, "by_dialpeer") == 0) {
        strlcpy(order_sql_string, "RAND() ASC", sizeof(order_sql_string));
    }

    // format dial peer id into string like this '1,12,6,8,'
    // this string will be used in mysql query to fetch only active dial peers
    if (failover == 1) {
        for (i = 0; i < cd->failover_1_dpeers_count; i++) {
            char tmp_buffer[32] = "";
            sprintf(tmp_buffer, "%d,", cd->failover_1_dpeers[i].id);
            strlcat(dpeer_id_list, tmp_buffer, sizeof(dpeer_id_list));
        }
        routing_group_id = cd->op->failover_1_routing_group_id;
    } else if (failover == 2) {
        for (i = 0; i < cd->failover_2_dpeers_count; i++) {
            char tmp_buffer[32] = "";
            sprintf(tmp_buffer, "%d,", cd->failover_2_dpeers[i].id);
            strlcat(dpeer_id_list, tmp_buffer, sizeof(dpeer_id_list));
        }
        routing_group_id = cd->op->failover_2_routing_group_id;
    } else {
        for (i = 0; i < cd->dpeers_count; i++) {
            char tmp_buffer[32] = "";
            sprintf(tmp_buffer, "%d,", cd->dpeers[i].id);
            strlcat(dpeer_id_list, tmp_buffer, sizeof(dpeer_id_list));
        }
        routing_group_id = cd->op->routing_group_id;
    }

    // remove last separator
    dpeer_id_list[strlen(dpeer_id_list) - 1] = '\0';

    // split dst into parts
    m2_format_prefix_sql(prefix_sql_line, cd->dst);

    sprintf(query, "SELECT D.*, GROUP_CONCAT(incoming_hgc.code, '=', outgoing_hgc.code) as 'hgc_mapping' FROM ("
        "SELECT * FROM ("
        "SELECT B.*, ratedetails.rate, ratedetails.increment_s, ratedetails.min_time, ratedetails.connection_fee, ratedetails.blocked FROM ("
        "SELECT rates.id AS 'rates_id', devices.id AS 'tpid', rates.prefix, "
        "%s as 'devname', devices.user_id, currencies.exchange_rate, "
        "0 as 'empty2', devices.host, dpeer_tpoints.tp_weight AS 'tpw', dpeer_tpoints.tp_percent AS 'tpp', "
        "devices.tp_src_regexp, devices.tp_src_deny_regexp, devices.tp_tech_prefix, "
        "devices.timeout, users.balance, users.balance_max, tariffs.id as 'tid', "
        "IF(LENGTH(tp_src_regexp) > 0,'%s' REGEXP tp_src_regexp,0) as 'src_regexp_result', IF(LENGTH(tp_src_deny_regexp) > 0,'%s' REGEXP tp_src_deny_regexp,0) as 'src_deny_regexp_result', devices.port, "
        "IF(timezones.offset IS NULL,NULL,IF(WEEKDAY(DATE_ADD(UTC_TIMESTAMP(), INTERVAL timezones.offset SECOND)) > 4,'FD','WD')) AS 'tp_daytype', "
        "IF(timezones.offset IS NULL,NULL,DATE_ADD(UTC_TIMESTAMP(), INTERVAL timezones.offset SECOND)) AS 'tp_datetime', "
        "users.time_zone, timezones.offset, rates.effective_from, custom_sip_header, rgroup_dpeers.dial_peer_id, rgroup_dpeers.dial_peer_priority, "
        "devices.max_timeout, devices.callerid_number_pool_id, devices.grace_time, interpret_noanswer_as_failed, interpret_busy_as_failed, devices.tp_capacity, "
        "users.call_limit, devices.cps_call_limit, devices.cps_period, devices.periodic_check, devices.alive, devices.tp_source_transformation, devices.callerid, "
        "devices.disable_q850, devices.forward_rpid, devices.forward_pai, devices.bypass_media, enforce_lega_codecs, use_pai_if_cid_anonymous, "
        "callerid_number_pool_type, callerid_number_pool_deviation, tp_call_limit, tp_cps "
        "FROM dpeer_tpoints "
        "JOIN devices ON (devices.id = dpeer_tpoints.device_id AND devices.tp_active = 1 AND dpeer_tpoints.active = 1) "
        "JOIN users ON (users.id = devices.user_id AND users.blocked = 0) "
        "LEFT JOIN timezones ON timezones.zone = users.time_zone "
        "JOIN tariffs ON (devices.tp_tariff_id = tariffs.id) "
        "LEFT JOIN currencies ON currencies.name = tariffs.currency "
        "LEFT JOIN rates FORCE INDEX FOR JOIN (prefix) ON ((rates.tariff_id = tariffs.id) AND rates.prefix IN (%s) AND (rates.effective_from < NOW() OR rates.effective_from IS NULL)) "
        "JOIN rgroup_dpeers ON rgroup_dpeers.dial_peer_id = dpeer_tpoints.dial_peer_id "
        "WHERE dpeer_tpoints.device_id != %d AND dpeer_tpoints.dial_peer_id IN (%s) AND rgroup_dpeers.routing_group_id = %d%s) AS B "
        "JOIN ratedetails ON (ratedetails.rate_id = B.rates_id AND (IF(tp_daytype IS NULL,ratedetails.daytype = '%s',ratedetails.daytype = tp_daytype) OR ratedetails.daytype = '') AND IF(tp_datetime IS NULL,'%s',TIME(tp_datetime)) BETWEEN ratedetails.start_time AND ratedetails.end_time) ORDER BY LENGTH(B.prefix) DESC, B.effective_from DESC) AS C "
        "GROUP BY C.dial_peer_id, C.tpid) AS D "
        "LEFT JOIN hgc_mappings ON hgc_mappings.device_id = D.tpid "
        "LEFT JOIN hangupcausecodes AS incoming_hgc ON incoming_hgc.id = hgc_mappings.hgc_incoming_id "
        "LEFT JOIN hangupcausecodes AS outgoing_hgc ON outgoing_hgc.id = hgc_mappings.hgc_outgoing_id "
        "GROUP BY D.tpid, D.dial_peer_id ORDER BY D.dial_peer_priority ASC, %s, RAND() ASC",
        tp_description_sql, cd->src, cd->src, prefix_sql_line, cd->op->id, dpeer_id_list, routing_group_id, skip_zero_percent, cd->daytype, cd->time, order_sql_string);

    // IMPORTANT: m2_tp_load_from_db() in m2_tp.c reads TP for the cache - edit SQL there accordingly


    meter.m2_tprate_sql_count_start++;
    double start_time = m2_get_current_time();

    if (m2_mysql_query(cd, query, &connection)) {
        return 1;
    }

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_tprate_sql_time += run_time;
    meter.m2_tprate_sql_count++;
    if (run_time > meter.m2_tprate_sql_time_max) {
        meter.m2_tprate_sql_time_max = run_time;
    }
    if (run_time > meter.m2_tprate_sql_time_maxps) {
        meter.m2_tprate_sql_time_maxps = run_time;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {

        while ((row = mysql_fetch_row(result))) {

            int src_regexp_status = 0;
            int src_deny_regexp_status = 0;
            double minimal_rate_margin = 0;
            double minimal_rate_margin_percent = 0;

            // shortcuts to cd->dpeers[xx]->tpoints[yyyy]->zzzz
            tpoints_t *tpoints_p = NULL;
            int *tpoints_c = NULL;

            // DO SOME CHECKING BEFORE PICKING PROPER TERMINATORS

            // find to which dial peer this tp belongs to and get its index
            int dp_index = -1;
            int i = 0;
            if (row[26]) {
                int dpeer_id = atoi(row[26]);
                if (failover == 1) {
                    for (i = 0; i < cd->failover_1_dpeers_count; i++) {
                        if (cd->failover_1_dpeers[i].id == dpeer_id) {
                            dp_index = i;
                            break;
                        }
                    }
                } else if (failover == 2) {
                    for (i = 0; i < cd->failover_2_dpeers_count; i++) {
                        if (cd->failover_2_dpeers[i].id == dpeer_id) {
                            dp_index = i;
                            break;
                        }
                    }
                } else {
                    for (i = 0; i < cd->dpeers_count; i++) {
                        if (cd->dpeers[i].id == dpeer_id) {
                            dp_index = i;
                            break;
                        }
                    }
                }
            }

            // if could not find dp index, something is wrong...
            // otherwise just read some dial peer data
            if (dp_index == -1) {
                m2_log(M2_ERROR, "Could not assign TP [%s] to proper DP\n", row[1] == NULL ? "null" : row[1]);
                return 1;
            } else {
                if (failover == 1) {
                    // get minimal rate margin
                    minimal_rate_margin = cd->failover_1_dpeers[dp_index].minimal_rate_margin;
                    minimal_rate_margin_percent = cd->failover_1_dpeers[dp_index].minimal_rate_margin_percent;
                    // pointer to termination points count in dial peer
                    tpoints_c = &cd->failover_1_dpeers[dp_index].tpoints_count;
                    // allocate memory for tp
                    cd->failover_1_dpeers[dp_index].tpoints = realloc(cd->failover_1_dpeers[dp_index].tpoints, (*tpoints_c + 1) * sizeof(tpoints_t));
                    memset(&cd->failover_1_dpeers[dp_index].tpoints[*tpoints_c], 0, sizeof(tpoints_t));
                    cd->failover_1_dpeers[dp_index].tpoints_rand = realloc(cd->failover_1_dpeers[dp_index].tpoints_rand, (*tpoints_c + 1) * sizeof(tpoints_rand_t));
                    memset(&cd->failover_1_dpeers[dp_index].tpoints_rand[*tpoints_c], 0, sizeof(tpoints_rand_t));
                    // pointer to termination points in dial peer
                    tpoints_p = cd->failover_1_dpeers[dp_index].tpoints;
                } else if (failover == 2) {
                    // get minimal rate margin
                    minimal_rate_margin = cd->failover_2_dpeers[dp_index].minimal_rate_margin;
                    minimal_rate_margin_percent = cd->failover_2_dpeers[dp_index].minimal_rate_margin_percent;
                    // pointer to termination points count in dial peer
                    tpoints_c = &cd->failover_2_dpeers[dp_index].tpoints_count;
                    // allocate memory for tp
                    cd->failover_2_dpeers[dp_index].tpoints = realloc(cd->failover_2_dpeers[dp_index].tpoints, (*tpoints_c + 1) * sizeof(tpoints_t));
                    memset(&cd->failover_2_dpeers[dp_index].tpoints[*tpoints_c], 0, sizeof(tpoints_t));
                    cd->failover_2_dpeers[dp_index].tpoints_rand = realloc(cd->failover_2_dpeers[dp_index].tpoints_rand, (*tpoints_c + 1) * sizeof(tpoints_rand_t));
                    memset(&cd->failover_2_dpeers[dp_index].tpoints_rand[*tpoints_c], 0, sizeof(tpoints_rand_t));
                    // pointer to termination points in dial peer
                    tpoints_p = cd->failover_2_dpeers[dp_index].tpoints;
                } else {
                    // get minimal rate margin
                    minimal_rate_margin = cd->dpeers[dp_index].minimal_rate_margin;
                    minimal_rate_margin_percent = cd->dpeers[dp_index].minimal_rate_margin_percent;
                    // pointer to termination points count in dial peer
                    tpoints_c = &cd->dpeers[dp_index].tpoints_count;
                    // allocate memory for tp
                    cd->dpeers[dp_index].tpoints = realloc(cd->dpeers[dp_index].tpoints, (*tpoints_c + 1) * sizeof(tpoints_t));
                    memset(&cd->dpeers[dp_index].tpoints[*tpoints_c], 0, sizeof(tpoints_t));
                    cd->dpeers[dp_index].tpoints_rand = realloc(cd->dpeers[dp_index].tpoints_rand, (*tpoints_c + 1) * sizeof(tpoints_rand_t));
                    memset(&cd->dpeers[dp_index].tpoints_rand[*tpoints_c], 0, sizeof(tpoints_rand_t));
                    // pointer to termination points in dial peer
                    tpoints_p = cd->dpeers[dp_index].tpoints;
                }
            }

            if (tpoints_p == NULL || tpoints_c == NULL) {
                m2_log(M2_ERROR, "Pointers tpoints_p and tpoints_c are null\n");
                return 1;
            }

            // this function parses majority of row's values
            m2_tp_parse_mysql_row(row, &tpoints_p[*tpoints_c]);

            // these fields are used here locally for each separate src, no need to retrieve them to tp structure
            if (row[17]) src_regexp_status = atoi(row[17]); else src_regexp_status = 0;
            if (row[18]) src_deny_regexp_status = atoi(row[18]); else src_deny_regexp_status = 0;

            // special handling with values from the cd structure
            if (row[20] && row[21]) {
            strlcpy(tpoints_p[*tpoints_c].tp_user_daytype, row[20], sizeof(tpoints_p[*tpoints_c].tp_user_daytype));
                strlcpy(tpoints_p[*tpoints_c].tp_user_date, row[21], sizeof(tpoints_p[*tpoints_c].tp_user_date));
            } else {
                strlcpy(tpoints_p[*tpoints_c].tp_user_daytype, cd->daytype, sizeof(tpoints_p[*tpoints_c].tp_user_daytype));
                strlcpy(tpoints_p[*tpoints_c].tp_user_date, cd->date, sizeof(tpoints_p[*tpoints_c].tp_user_date));
                strlcpy(tpoints_p[*tpoints_c].tp_user_time, cd->time, sizeof(tpoints_p[*tpoints_c].tp_user_time));
            }

            // Do NOT add new fields here. Add new fields in the m2_tp_parse_mysql_row() [m2_tp.c] (do not forget to change row[xx] in the folowing lines)
            // and adjust following indexes for row array to make these fields last
            // !!!!!!!!!!!!!!! these 6 rows are returned last   !!!!!!!!!!!!!!!!!!!!

            if (row[51]) tpoints_p[*tpoints_c].tp_rate = atof(row[51]); else tpoints_p[*tpoints_c].tp_rate = 0;
            if (row[52]) tpoints_p[*tpoints_c].tp_increment = atoi(row[52]); else tpoints_p[*tpoints_c].tp_increment = 0;
            if (row[53]) tpoints_p[*tpoints_c].tp_min_time = atoi(row[53]); else tpoints_p[*tpoints_c].tp_min_time = 0;
            if (row[54]) tpoints_p[*tpoints_c].tp_connection_fee = atof(row[54]); else tpoints_p[*tpoints_c].tp_connection_fee = 0;
            if (row[55]) tpoints_p[*tpoints_c].tp_blocked_rate = atoi(row[55]); else tpoints_p[*tpoints_c].tp_blocked_rate = 0;
            if (row[56]) strlcpy(tpoints_p[*tpoints_c].tp_hgc_mapping, row[56], sizeof(tpoints_p[*tpoints_c].tp_hgc_mapping)); else strlcpy(tpoints_p[*tpoints_c].tp_hgc_mapping, "", sizeof(tpoints_p[*tpoints_c].tp_hgc_mapping));

            // assign user to termination point
            tpoints_p[*tpoints_c].user = m2_find_user(tpoints_p[*tpoints_c].tp_user_id);

            if (!tpoints_p[*tpoints_c].user) {
                m2_log(M2_WARNING, "Could not assign user to TP [%d]!\n", tpoints_p[*tpoints_c].tp_user_id);
                cd->last_tp_hangupcause = 0;
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }

            // handle too high values (we don't want overflow when doing mathematical operations)
            if (tpoints_p[*tpoints_c].tp_user_balance_limit > 1000000000) {
                m2_log(M2_NOTICE, "Balance limit (%f) is too high! Value will be set to 1000000000\n", tpoints_p[*tpoints_c].tp_user_balance_limit);
                tpoints_p[*tpoints_c].tp_user_balance_limit = 1000000000;
            }

            // calculate rate after exchange
            if (tpoints_p[*tpoints_c].tp_exchange_rate != 0) {
                tpoints_p[*tpoints_c].tp_rate_after_exchange = tpoints_p[*tpoints_c].tp_rate / tpoints_p[*tpoints_c].tp_exchange_rate;
            } else {
                tpoints_p[*tpoints_c].tp_exchange_rate = 1;
                tpoints_p[*tpoints_c].tp_rate_after_exchange = tpoints_p[*tpoints_c].tp_rate;
            }

            // enforce hgc mapping from /etc/m2/system.conf
            if (enforced_global_hgc > 0) {
                // hgc mapping is set on originator, so no need to set same thing for terminator
                strlcpy(tpoints_p[*tpoints_c].tp_hgc_mapping, "", sizeof(tpoints_p[*tpoints_c].tp_hgc_mapping));
            }


            // --- Checking TP Rate validity

            if (m2_tp_rate_check_validity(cd, &tpoints_p[*tpoints_c], minimal_rate_margin, minimal_rate_margin_percent)) {
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }

            // --- Check regexp validity

            // check if src matches terminators's regexp
            if (src_regexp_status == 0) {
                m2_log(M2_NOTICE, "Skipping TP [%d%s]. Src [%s] does not match src regexp [%s]\n",
                    tpoints_p[*tpoints_c].tp_id, tpoints_p[*tpoints_c].tp_description, cd->src, tpoints_p[*tpoints_c].tp_src_regexp);
                cd->last_tp_hangupcause = 321;
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }

            // check if src is not denied by terminators's src deny regexp
            if (src_deny_regexp_status == 1) {
                m2_log(M2_NOTICE, "Skipping TP [%d%s]. Src [%s] is denied by regexp [%s]\n",
                    tpoints_p[*tpoints_c].tp_id, tpoints_p[*tpoints_c].tp_description, cd->src, tpoints_p[*tpoints_c].tp_src_deny_regexp);
                cd->last_tp_hangupcause = 322;
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }


            // --- Checking TP validity

            if (m2_tp_check_validity(cd, &tpoints_p[*tpoints_c], dp_index)) {
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }

            // CPS check

            check_terminator_cps = 1;
            if (terminator_cps_count < 48) {
                int x = 0;
                for (x = 0; x < terminator_cps_count; x++) {
                    if (terminator_cps_array[x] == tpoints_p[*tpoints_c].tp_id) {
                        check_terminator_cps = 0;
                    }
                }
                if (check_terminator_cps) {
                    terminator_cps_array[terminator_cps_count] = tpoints_p[*tpoints_c].tp_id;
                    terminator_cps_count++;
                }
            }


            // check cps
            m2_update_cps_data(tpoints_p[*tpoints_c].tp_id, tpoints_p[*tpoints_c].tp_cps_limit, tpoints_p[*tpoints_c].tp_cps_period, cd);
            if (check_terminator_cps && m2_check_cps(tpoints_p[*tpoints_c].tp_id, cd)) {
                m2_log(M2_WARNING, "Skipping TP [%d%s]. CPS limitation reached\n", tpoints_p[*tpoints_c].tp_id, tpoints_p[*tpoints_c].tp_description);
                cd->last_tp_hangupcause = 329;
                memset(&tpoints_p[*tpoints_c], 0, sizeof(tpoints_t));
                goto skip_tp_label;
            }


            // --- End of TP checks


            *tpoints_c += 1;
            if (failover == 1) {
                cd->failover_1_tp_count += 1;
            } else if (failover == 2) {
                cd->failover_2_tp_count += 1;
            } else {
                cd->tp_count += 1;
            }

            skip_tp_label:;

        }

        mysql_free_result(result);

    }

    return 0;

}




/*
    Show terminator info and clean empty dial peers
*/


static void m2_show_tp(calldata_t *cd, int failover) {

    dialpeers_t *dpeers = NULL;
    int dpeers_count = 0;

    if (failover == 1) {
        dpeers = cd->failover_1_dpeers;
        dpeers_count = cd->failover_1_dpeers_count;
    } else if (failover == 2) {
        dpeers = cd->failover_2_dpeers;
        dpeers_count = cd->failover_2_dpeers_count;
    } else {
        dpeers = cd->dpeers;
        dpeers_count = cd->dpeers_count;
    }

    int i = 0, j = 0;
    for (i = 0; i < dpeers_count; i++) {
        if (dpeers[i].tpoints_count) {
            if (failover == 1) {
                m2_log(M2_NOTICE, "Failover #1 TP list for DP [%d%s], order by: %s\n", dpeers[i].id, dpeers[i].name, cd->op->routing_algorithm);
            } else if (failover == 2) {
                m2_log(M2_NOTICE, "Failover #2 TP list for DP [%d%s], order by: %s\n", dpeers[i].id, dpeers[i].name, cd->op->routing_algorithm);
            } else {
                m2_log(M2_NOTICE, "TP list for DP [%d%s], order by: %s\n", dpeers[i].id, dpeers[i].name, cd->op->routing_algorithm);
            }
            for (j = 0; j < dpeers[i].tpoints_count; j++) {

                m2_tp_print_data(cd, &dpeers[i].tpoints[j]);

            }
        } else {
            m2_log(M2_NOTICE, "DP [%d%s] does not have any suitable TP. Skipping this DP\n", dpeers[i].id, dpeers[i].name);
        }
    }

    // remove empty dialpeers
    int done = 0;
    while (done == 0) {
        done = 1;
        if (failover == 1) {
            for (i = 0; i < cd->failover_1_dpeers_count; i++) {
                if (cd->failover_1_dpeers[i].tpoints_count == 0) {
                    done = 0;
                    if (cd->failover_1_dpeers[i].tpoints) free(cd->failover_1_dpeers[i].tpoints);
                    if (cd->failover_1_dpeers[i].tpoints_rand) free(cd->failover_1_dpeers[i].tpoints_rand);
                    if (i < (cd->failover_1_dpeers_count - 1)) {
                        memmove(&cd->failover_1_dpeers[i], &cd->failover_1_dpeers[i + 1], (cd->failover_1_dpeers_count - i - 1) * sizeof(dialpeers_t));
                    }
                    cd->failover_1_dpeers = realloc(cd->failover_1_dpeers, (cd->failover_1_dpeers_count - 1) * sizeof(dialpeers_t));
                    cd->failover_1_dpeers_count--;
                    break;
                }
            }
        } else if (failover == 2) {
            for (i = 0; i < cd->failover_2_dpeers_count; i++) {
                if (cd->failover_2_dpeers[i].tpoints_count == 0) {
                    done = 0;
                    if (cd->failover_2_dpeers[i].tpoints) free(cd->failover_2_dpeers[i].tpoints);
                    if (cd->failover_2_dpeers[i].tpoints_rand) free(cd->failover_2_dpeers[i].tpoints_rand);
                    if (i < (cd->failover_2_dpeers_count - 1)) {
                        memmove(&cd->failover_2_dpeers[i], &cd->failover_2_dpeers[i + 1], (cd->failover_2_dpeers_count - i - 1) * sizeof(dialpeers_t));
                    }
                    cd->failover_2_dpeers = realloc(cd->failover_2_dpeers, (cd->failover_2_dpeers_count - 1) * sizeof(dialpeers_t));
                    cd->failover_2_dpeers_count--;
                    break;
                }
            }
        } else {
            for (i = 0; i < cd->dpeers_count; i++) {
                if (cd->dpeers[i].tpoints_count == 0) {
                    done = 0;
                    if (cd->dpeers[i].tpoints) free(cd->dpeers[i].tpoints);
                    if (cd->dpeers[i].tpoints_rand) free(cd->dpeers[i].tpoints_rand);
                    if (i < (cd->dpeers_count - 1)) {
                        memmove(&cd->dpeers[i], &cd->dpeers[i + 1], (cd->dpeers_count - i - 1) * sizeof(dialpeers_t));
                    }
                    cd->dpeers = realloc(cd->dpeers, (cd->dpeers_count - 1) * sizeof(dialpeers_t));
                    cd->dpeers_count--;
                    break;
                }
            }
        }
    }

}


/*
    Check if SRC or SRC and DST is matching Rule-Set
*/


static int m2_check_rule_sets(calldata_t *cd) {

    char number[256] = "";
    int dst_is_matching = 0;
    int src_is_matching = 0;
    int dst_matches = 0;

    if (cd->op->use_pai_as_number && strlen(cd->originator_pai_number)) {
        strcpy(number, cd->originator_pai_number);
        m2_log(M2_DEBUG, "PAI Number: %s will be used as SRC number\n", number);
    } else {
        strcpy(number, cd->callerid_number);
        m2_log(M2_DEBUG, "CallerID Number: %s will be used as SRC number\n", number);
    }

    src_is_matching = m2_number_is_matching_rule_set(cd, number, cd->op->rule_set_id);
    /*
      op_dst_matches has 3 states
        0 - do not use
        1 - matches
        2 - not-matches
    */
    if (cd->op->dst_matches) {
        /*
          dst_matches has 2 states
            1 - matches, if op_dst_matches == 1
            0 - not-matches, if op_dst_matches == 2
        */
        if (cd->op->dst_matches == 1) dst_matches = 1;
        dst_is_matching = m2_number_is_matching_rule_set(cd, cd->dst, cd->op->dst_rule_set_id);

        if (src_is_matching == cd->op->src_matches && dst_is_matching == dst_matches) {
            m2_log(M2_NOTICE, "Tariff [%d] by SRC and DST numbers rule-sets will be applied\n", cd->op->match_tariff_id);
            return 1;
        } else {
            return 0;
        }

    } else if (src_is_matching == cd->op->src_matches) {
        m2_log(M2_NOTICE, "Tariff [%d] by SRC number rule-set will be applied\n", cd->op->match_tariff_id);
        return 1;
    } else {
        return 0;
    }

}


/*
    Check if number is in Rule-Set
*/


static int m2_number_is_matching_rule_set(calldata_t *cd, char *number, int rule_set_id){
    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char query[2048] = "";
    int found = 0;
    char number_from_db[256] = "";

    sprintf(query, "SELECT number FROM numbers WHERE '%s' LIKE numbers.number AND number_pool_id = %d LIMIT 1", number, rule_set_id);
    if (m2_mysql_query(cd, query, &connection)) {
        return 0;
    }

    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        while ((row = mysql_fetch_row(result))) {
            if (row[0]) {
                strlcpy(number_from_db, row[0], sizeof(number_from_db));
                found = 1;
            }
        }
        mysql_free_result(result);
    }

    if (found) {
        m2_log(M2_DEBUG, "Number [%s] matches prefix [%s] in Rule-Set! NumberPool [%d]\n", number, number_from_db, rule_set_id);
    } else {
        m2_log(M2_DEBUG, "Number [%s] is not in Rule-Set! NumberPool [%d]\n", number, rule_set_id);
    }

    return found;
}

