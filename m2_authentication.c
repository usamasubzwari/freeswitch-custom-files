
static int m2_authentication(calldata_t *cd) {

    m2_log(M2_NOTICE, "----------------------------------- AUTHENTICATION ------------------------------------\n");

    MYSQL_RES *result = NULL;
    MYSQL_ROW row;
    int connection = 0;

    char *callerid_number_ptr = NULL;
    char *callerid_name_ptr = NULL;

    char query[4096] = "";
    char condition[512] = "";
    int authenticated = 0;
    int port = 5060;
    int inc_hgc = 0;
    int out_hgc = 0;

    char op_name_sql[30] = "''";
    char user_name_sql[30] = "''";
    char tariff_name_sql[30] = "''";
    char routing_group_name_sql[30] = "''";
    char failover_1_routing_group_name_sql[30] = "''";
    char failover_2_routing_group_name_sql[30] = "''";

    int hgc_value = 0;

    cd->op->server_id = -1;

    // let's check our OP cache (list) first
    int auth_by_op_list = 0;
    op_t *op = NULL;

    m2_mutex_lock(CONNP_LIST_LOCK);

    op = m2_find_op_for_authentication(cd);
    if (op) {
        memcpy(cd->op, op, sizeof(op_t));
        auth_by_op_list = 1;
        authenticated = 1;

        // Checking IP in the cache
        cd->cached_call = 0;
        hgc_value = m2_hgc_cache_get_connp(cd);
        if (hgc_value) {
            m2_log(M2_NOTICE, "HGC CACHE: [%s:%i] tech_prefix [%s] value [%i] found in the cache (connp_index)\n", cd->op->ipaddr, cd->op->port, cd->op->tech_prefix, hgc_value);
            m2_set_hangupcause(cd, hgc_value);
            cd->cached_call = 1;                                  // marking that this call was found in the cache

            m2_mutex_unlock(CONNP_LIST_LOCK);
            return 1;
        }
    }

    m2_mutex_unlock(CONNP_LIST_LOCK);


    // if not authenticated by op list/cache - read from db
    if (!auth_by_op_list) {

        if (cd->op->port) {
            port = cd->op->port;
        }

        if (cd->call_tracing_accountcode) {
            sprintf(condition, "AND devices.id = %d", cd->call_tracing_accountcode);
        } else {
            sprintf(condition, "AND (INET_ATON('%s') BETWEEN ipaddr_range_start AND ipaddr_range_end)", cd->op->ipaddr);
        }

        if (show_entity_names) {
            strcpy(op_name_sql, "devices.description");
            strcpy(user_name_sql, "users.username");
            strcpy(routing_group_name_sql, "routing_groups.name");
            strcpy(failover_1_routing_group_name_sql, "failover_rg_2.name");
            strcpy(failover_2_routing_group_name_sql, "failover_rg_3.name");
            strcpy(routing_group_name_sql, "routing_groups.name");
            strcpy(tariff_name_sql, "tariffs.name");
        }

        sprintf(query, "SELECT op_tech_prefix, op_routing_algorithm, op_routing_group_id, op_tariff_id, op_capacity, "
           "user_id, balance, %s, op_src_regexp, op_src_deny_regexp, users.blocked, users.balance_min, devices.id, cps_call_limit, cps_period, "
           "IF(LENGTH(op_src_regexp) > 0, '%s' REGEXP op_src_regexp, 0) AS 'src_regexp_result', IF(LENGTH(op_src_deny_regexp) > 0, '%s' REGEXP op_src_deny_regexp, 0) AS 'src_deny_regexp_result', %s, "
           "IF(SUBSTR(IF(use_invite_dst = 1, '%s', '%s'), 1, LENGTH(op_tech_prefix)) = op_tech_prefix, SUBSTR(IF(use_invite_dst = 1, '%s', '%s'), 1, LENGTH(op_tech_prefix)), '') AS 'tech_prefix_result', "
           "users.call_limit, %s, devices.port, %s, "
           "IF(timezones.offset IS NULL,NULL,IF(WEEKDAY(DATE_ADD(UTC_TIMESTAMP(), INTERVAL timezones.offset SECOND)) > 4,'FD','WD')) AS 'daytype', "
           "IF(timezones.offset IS NULL,NULL,DATE_ADD(UTC_TIMESTAMP(), INTERVAL timezones.offset SECOND)) AS 'user_date', "
           "users.time_zone, timezones.offset, custom_sip_header, devices.callerid, devices.allow, devices.max_timeout, devices.timeout, "
           "GROUP_CONCAT(incoming_hgc.code, '=', outgoing_hgc.code) AS 'hgc_mapping', callerid_number_pool_id, enable_static_list, static_list_id, devices.grace_time, "
           "insecure, routing_groups.parent_routing_group_id, enable_static_source_list, static_source_list_id, failover_rg_2.parent_routing_group_id, "
           "server_devices.id AS device_server, hgc_mappings.hgc_incoming_id, outgoing_hgc.code, op_custom_tariff_id, op_destination_transformation, quality_routing_id, "
           "op_source_transformation, disable_q850, forward_rpid, forward_pai, bypass_media, use_invite_dst, inherit_codec, max_call_rate, ring_instead_progress, "
           "set_sip_contact, IF('%d' = port, 1, 0) AS 'port_match', change_rpidpai_host, op_match_tariff_id, op_use_pai_as_number, op_number_pool_id, op_callerid_matches, "
           "op_dst_matches, op_dst_number_pool_id, ignore_183nosdp, op_fake_ring, callerid_number_pool_type, callerid_number_pool_deviation, %s, %s, us_jurisdictional_routing, "
           "op_tariff_intra, op_tariff_inter, op_tariff_indeter "
           "FROM devices "
           "JOIN users ON users.id = user_id "
           "JOIN tariffs ON tariffs.id = devices.op_tariff_id "
           "LEFT JOIN routing_groups ON routing_groups.id = devices.op_routing_group_id "
           "LEFT JOIN routing_groups AS failover_rg_2 ON routing_groups.parent_routing_group_id = failover_rg_2.id "
           "LEFT JOIN routing_groups AS failover_rg_3 ON failover_rg_2.parent_routing_group_id = failover_rg_3.id "
           "LEFT JOIN timezones ON timezones.zone = users.time_zone "
           "LEFT JOIN hgc_mappings ON hgc_mappings.device_id = devices.id "
           "LEFT JOIN hangupcausecodes AS incoming_hgc ON incoming_hgc.id = hgc_mappings.hgc_incoming_id "
           "LEFT JOIN hangupcausecodes AS outgoing_hgc ON outgoing_hgc.id = hgc_mappings.hgc_outgoing_id "
           "LEFT JOIN server_devices ON (server_devices.device_id = devices.id AND server_devices.server_id = %d) "
           "WHERE op = 1 AND op_active = 1 %s "
           "GROUP BY devices.id "
           "ORDER BY LENGTH(tech_prefix_result) DESC, LENGTH(op_tech_prefix) ASC, src_deny_regexp_result ASC, src_regexp_result DESC, port_match DESC, devices.id ASC LIMIT 1",
           tariff_name_sql, cd->src, cd->src, routing_group_name_sql, cd->invite_dst, cd->dst, cd->invite_dst, cd->dst, op_name_sql,
           user_name_sql, port, failover_1_routing_group_name_sql, failover_2_routing_group_name_sql, cd->server_id, condition);


        meter.m2_authen_sql_count_start++;
        double start_time = m2_get_current_time();

        if (m2_mysql_query(cd, query, &connection)) {
            m2_set_hangupcause(cd, 301);

            // saving into cache
            m2_hgc_cache_set(cd, 301, CACHE_TTL_HGC301);

            return 1;
        }

        m2_log(M2_DEBUG, "OP CACHE: Authentication SQL completed.\n");

        // saving metering stats
        double run_time = m2_get_current_time() - start_time;
        meter.m2_authen_sql_time += run_time;
        meter.m2_authen_sql_count++;
        if (run_time > meter.m2_authen_sql_time_max) {
            meter.m2_authen_sql_time_max = run_time;
        }
        if (run_time > meter.m2_authen_sql_time_maxps) {
            meter.m2_authen_sql_time_maxps = run_time;
        }

        // query succeeded, get results and mark connection as available
        result = mysql_store_result(&mysql[connection]);
        mysql_connections[connection] = 0;

        if (result) {

            while ((row = mysql_fetch_row(result))) {

                if (row[0]) strlcpy(cd->op->tech_prefix, row[0], sizeof(cd->op->tech_prefix)); else strlcpy(cd->op->tech_prefix, "", sizeof(cd->op->tech_prefix));
                if (row[1]) strlcpy(cd->op->routing_algorithm, row[1], sizeof(cd->op->routing_algorithm)); else strlcpy(cd->op->routing_algorithm, "", sizeof(cd->op->routing_algorithm));
                if (row[2]) cd->op->routing_group_id = atoi(row[2]); else cd->op->routing_group_id = 0;
                if (row[3]) {
                    cd->op->tariff_id = atoi(row[3]);
                    cd->op->original_tariff_id = cd->op->tariff_id;
                } else {
                    cd->op->tariff_id = 0;
                    cd->op->original_tariff_id = 0;
                }
                if (row[4]) cd->op->capacity = atoi(row[4]); else cd->op->capacity = 0;
                if (row[5]) cd->op->user_id = atoi(row[5]); else cd->op->user_id = 0;
                if (row[6]) cd->op->user_balance = atof(row[6]); else cd->op->user_balance = 0;
                if (row[7] && strlen(row[7])) sprintf(cd->op->tariff_name, ":%s", row[7]); else strcpy(cd->op->tariff_name, "");
                if (row[8]) strlcpy(cd->op->src_regexp, row[8], sizeof(cd->op->src_regexp)); else strlcpy(cd->op->src_regexp, "", sizeof(cd->op->src_regexp));
                if (row[9]) strlcpy(cd->op->src_deny_regexp, row[9], sizeof(cd->op->src_deny_regexp)); else strlcpy(cd->op->src_deny_regexp, "", sizeof(cd->op->src_deny_regexp));
                if (row[10]) cd->op->user_blocked = atoi(row[10]); else cd->op->user_blocked = 0;
                if (row[11]) cd->op->user_balance_limit = atof(row[11]); else cd->op->user_balance_limit = 0;
                if (row[12]) cd->op->id = atoi(row[12]); else cd->op->id = 0;
                if (row[13] && row[14]) {
                    m2_update_cps_data(cd->op->id, atoi(row[13]), atoi(row[14]), cd);
                }
                if (row[15]) cd->op->src_regexp_status = atoi(row[15]); else cd->op->src_regexp_status = 0;
                if (row[16]) cd->op->src_deny_regexp_status = atoi(row[16]); else cd->op->src_deny_regexp_status = 0;
                if (row[17] && strlen(row[17])) sprintf(cd->op->routing_group_name, ":%s", row[17]); else strcpy(cd->op->routing_group_name, "");
                if (row[18]) strlcpy(cd->op->tech_prefix_result, row[18], sizeof(cd->op->tech_prefix_result)); else strlcpy(cd->op->tech_prefix_result, "", sizeof(cd->op->tech_prefix_result));

                if (row[19]) cd->op->user_call_limit = atoi(row[19]); else cd->op->user_call_limit = 0;
                if (row[20] && strlen(row[20])) sprintf(cd->op->description, ":%s", row[20]); else strcpy(cd->op->description, "");
                if (row[21]) cd->op->allowed_port = atoi(row[21]); else cd->op->allowed_port = 0;
                if (row[22] && strlen(row[22])) sprintf(cd->op->user_name, ":%s", row[22]); else strcpy(cd->op->user_name, "");
                if (row[23] && row[24]) {
                    strlcpy(cd->op->user_daytype, row[23], sizeof(cd->op->user_daytype));
                    strlcpy(cd->op->user_date, row[24], sizeof(cd->op->user_date));
                    strlcpy(cd->op->user_time, row[24] + 11, sizeof(cd->op->user_time));
                } else {
                    strlcpy(cd->op->user_daytype, cd->daytype, sizeof(cd->op->user_daytype));
                    strlcpy(cd->op->user_date, cd->date, sizeof(cd->op->user_date));
                    strlcpy(cd->op->user_time, cd->time, sizeof(cd->op->user_time));
                }
                if (row[25]) strlcpy(cd->op->user_time_zone, row[25], sizeof(cd->op->user_time_zone)); else strlcpy(cd->op->user_time_zone, "", sizeof(cd->op->user_time_zone));
                if (row[26]) cd->op->user_time_zone_offset = atoi(row[26]); else cd->op->user_time_zone_offset = -1;
                if (row[27]) strlcpy(cd->op->custom_sip_header, row[27], sizeof(cd->op->custom_sip_header)); else strlcpy(cd->op->custom_sip_header, "", sizeof(cd->op->custom_sip_header));
                if (row[28] && strlen(row[28])) {
                    strlcpy(cd->op->callerid, row[28], sizeof(cd->op->callerid));
                } else {
                    strlcpy(cd->callerid_number, cd->src, sizeof(cd->callerid_number));
                }
                if (row[29]) {

                    char *pch;
                    char *saveptr;
                    char string[256] = "";

                    strlcpy(string, row[29], sizeof(string));
                    pch = strtok_r(string, ";", &saveptr);

                    while (pch != NULL) {
                        if (strcmp(pch, "alaw") == 0) {
                            strlcat(cd->op->allowed_codecs, "PCMA,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "PCMA") || strstr(cd->op->codec_list, "pcma")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "ulaw") == 0) {
                            strlcat(cd->op->allowed_codecs, "PCMU,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "PCMU") || strstr(cd->op->codec_list, "pcmu")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "gsm") == 0) {
                            strlcat(cd->op->allowed_codecs, "GSM,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "GSM") || strstr(cd->op->codec_list, "gsm")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "g729") == 0) {
                            strlcat(cd->op->allowed_codecs, "G729,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "G729") || strstr(cd->op->codec_list, "g729")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "g723") == 0) {
                            strlcat(cd->op->allowed_codecs, "G723,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "G723") || strstr(cd->op->codec_list, "g723")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "g722") == 0) {
                            strlcat(cd->op->allowed_codecs, "G722,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "G722") || strstr(cd->op->codec_list, "g722")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "g726") == 0) {
                            strlcat(cd->op->allowed_codecs, "G726-16,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "G726-16") || strstr(cd->op->codec_list, "g726-16")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "ilbc") == 0) {
                            strlcat(cd->op->allowed_codecs, "iLBC@30i,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "iLBC@30i") || strstr(cd->op->codec_list, "ilbc@30i")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "lpc10") == 0) {
                            strlcat(cd->op->allowed_codecs, "LPC,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "LPC") || strstr(cd->op->codec_list, "lpc")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "speex") == 0) {
                            strlcat(cd->op->allowed_codecs, "Speex,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "Speex") || strstr(cd->op->codec_list, "speex") || strstr(cd->op->codec_list, "SPEEX")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "opus") == 0) {
                            strlcat(cd->op->allowed_codecs, "OPUS,", sizeof(cd->op->allowed_codecs));
                            if (strstr(cd->op->codec_list, "OPUS") || strstr(cd->op->codec_list, "opus")) {
                                cd->op->codecs_are_allowed = 1;
                            }
                        }
                        if (strcmp(pch, "all") == 0) {
                            strlcat(cd->op->allowed_codecs, "PCMA,PCMU,GSM,G729,G722,G723,G726-16,iLBC@30i,LPC,Speex,OPUS", sizeof(cd->op->allowed_codecs));
                            cd->op->codecs_are_allowed = 1;
                        }
                        pch = strtok_r(NULL, ";", &saveptr);
                    }

                    if (strlen(cd->op->allowed_codecs)) {
                        cd->op->allowed_codecs[strlen(cd->op->allowed_codecs) - 1] = 0;
                    }

                }

                if (row[30]) cd->op->max_timeout = atoi(row[30]); else cd->op->max_timeout = 0;
                if (row[31]) cd->op->ringing_timeout = atoi(row[31]); else cd->op->ringing_timeout = 60;
                if (row[32]) strlcpy(cd->op->hgc_mapping, row[32], sizeof(cd->op->hgc_mapping)); else strlcpy(cd->op->hgc_mapping, "", sizeof(cd->op->hgc_mapping));
                if (row[33]) cd->op->callerid_number_pool_id = atoi(row[33]); else cd->op->callerid_number_pool_id = 0;
                if (row[34]) strlcpy(cd->op->enable_static_list, row[34], sizeof(cd->op->enable_static_list)); else strlcpy(cd->op->enable_static_list, "", sizeof(cd->op->enable_static_list));
                if (row[35]) cd->op->static_list_id = atoi(row[35]); else cd->op->static_list_id = 0;
                if (row[36]) cd->op->grace_time = atoi(row[36]); else cd->op->grace_time = 0;
                if (row[37]) {
                    if (strstr(row[37], "port")) {
                        cd->op->allow_any_port = 1;
                    } else {
                        cd->op->allow_any_port = 0;
                    }
                } else {
                    cd->op->allow_any_port = 0;
                }
                if (row[38]) cd->op->failover_1_routing_group_id = atoi(row[38]); else cd->op->failover_1_routing_group_id = 0;
                if (row[39]) strlcpy(cd->op->enable_static_src_list, row[39], sizeof(cd->op->enable_static_src_list)); else strlcpy(cd->op->enable_static_src_list, "", sizeof(cd->op->enable_static_src_list));
                if (row[40]) cd->op->static_src_list_id = atoi(row[40]); else cd->op->static_src_list_id = 0;
                if (row[41]) cd->op->failover_2_routing_group_id = atoi(row[41]); else cd->op->failover_2_routing_group_id = 0;
                if (row[42]) cd->op->server_id = atoi(row[42]); else cd->op->server_id = -1;
                if (row[43]) inc_hgc = atoi(row[43]); else inc_hgc = 0;
                if (row[44]) out_hgc = atoi(row[44]); else out_hgc = 0;
                if (row[45]) cd->op->custom_tariff_id = atoi(row[45]); else cd->op->custom_tariff_id = 0;
                if (row[46]) strlcpy(cd->op->dst_transformation, row[46], sizeof(cd->op->dst_transformation)); else strlcpy(cd->op->dst_transformation, "", sizeof(cd->op->dst_transformation));
                if (row[47]) cd->op->quality_routing_id = atoi(row[47]); else cd->op->quality_routing_id = 0;
                if (row[48]) strlcpy(cd->op->src_transformation, row[48], sizeof(cd->op->src_transformation)); else strlcpy(cd->op->src_transformation, "", sizeof(cd->op->src_transformation));
                if (row[49]) cd->op->disable_q850 = atoi(row[49]); else cd->op->disable_q850 = 0;
                if (row[50]) cd->op->forward_rpid = atoi(row[50]); else cd->op->forward_rpid = 1;
                if (row[51]) cd->op->forward_pai = atoi(row[51]); else cd->op->forward_pai = 1;
                if (row[52]) cd->op->bypass_media = atoi(row[52]); else cd->op->bypass_media = 0;
                if (row[53]) cd->op->use_invite_dst = atoi(row[53]); else cd->op->use_invite_dst = 0;
                if (row[54]) cd->op->inherit_codec = atoi(row[54]); else cd->op->inherit_codec = 0;
                if (row[55]) cd->op->user_max_call_rate = atof(row[55]); else cd->op->user_max_call_rate = 0;
                if (row[56]) cd->op->ring_instead_progress = atoi(row[56]); else cd->op->ring_instead_progress = 0;
                if (row[57]) cd->op->set_sip_contact = atoi(row[57]); else cd->op->set_sip_contact = 0;
                // row[58] port_match - used inside sql for sorting
                if (row[59]) cd->op->change_rpidpai_host = atoi(row[59]); else cd->op->change_rpidpai_host = 0;
                if (row[60]) cd->op->match_tariff_id = atoi(row[60]); else cd->op->match_tariff_id = 0;
                if (row[61]) cd->op->use_pai_as_number = atoi(row[61]); else cd->op->use_pai_as_number = 0;
                if (row[62]) cd->op->rule_set_id = atoi(row[62]); else cd->op->rule_set_id = 0;
                if (row[63]) cd->op->src_matches = atoi(row[63]); else cd->op->src_matches = 0;
                if (row[64]) cd->op->dst_matches = atoi(row[64]); else cd->op->dst_matches = 0;
                if (row[65]) cd->op->dst_rule_set_id = atoi(row[65]); else cd->op->dst_rule_set_id = 0;
                if (row[66]) cd->op->ignore_183nosdp = atoi(row[66]); else cd->op->ignore_183nosdp = 0;
                if (row[67]) cd->op->fake_ring = atoi(row[67]); else cd->op->fake_ring = 0;
                if (row[68]) strlcpy(cd->op->callerid_number_pool_type, row[68], sizeof(cd->op->callerid_number_pool_type)); else strlcpy(cd->op->callerid_number_pool_type, "", sizeof(cd->op->callerid_number_pool_type));
                if (row[69]) cd->op->callerid_number_pool_deviation = atoi(row[69]); else cd->op->callerid_number_pool_deviation = 0;
                if (row[70]) sprintf(cd->op->failover_1_routing_group_name, ":%s", row[70]); else strcpy(cd->op->failover_1_routing_group_name, "");
                if (row[71]) sprintf(cd->op->failover_2_routing_group_name, ":%s", row[71]); else strcpy(cd->op->failover_2_routing_group_name, "");
                if (row[72]) cd->op->us_jurisdictional_routing = atoi(row[72]); else cd->op->us_jurisdictional_routing = 0;
                if (row[73]) cd->op->tariff_intra_id = atoi(row[73]); else cd->op->tariff_intra_id = 0;
                if (row[74]) cd->op->tariff_inter_id = atoi(row[74]); else cd->op->tariff_inter_id = 0;
                if (row[75]) cd->op->tariff_indeter_id = atoi(row[75]); else cd->op->tariff_indeter_id = 0;

                if (cd->op->failover_1_routing_group_id < 0) cd->op->failover_1_routing_group_id = 0;
                if (cd->op->failover_2_routing_group_id < 0) cd->op->failover_2_routing_group_id = 0;

                authenticated = 1;

            }

            mysql_free_result(result);

        }

        if (!authenticated) {
            m2_log(M2_WARNING, "OP was not found by IP\n");
            m2_set_hangupcause(cd, 301);

            // saving into cache
            m2_hgc_cache_set(cd, 301, CACHE_TTL_HGC301);

            return 1;
        }

    } // if (!auth_by_op_list)

    if (strlen(cd->op->callerid)) {
        callerid_number_ptr = strstr(cd->op->callerid, "<");
        callerid_name_ptr = strstr(cd->op->callerid, "\"");

        if (callerid_number_ptr) {
            strcpy(cd->callerid_number, "");
            strlcpy(cd->callerid_number, callerid_number_ptr + 1, sizeof(cd->callerid_number));
            cd->callerid_number[strlen(cd->callerid_number) - 1] = 0;
            if (callerid_name_ptr) {
                strlcpy(cd->callerid_name, callerid_name_ptr + 1, strlen(cd->op->callerid) - strlen(callerid_number_ptr) - 2);
                cd->callerid_name[strlen(cd->op->callerid) - strlen(callerid_number_ptr) - 2] = 0;
            }
        } else if (callerid_name_ptr) {
            strlcpy(cd->callerid_name, callerid_name_ptr + 1, sizeof(cd->callerid_name));
            cd->callerid_name[strlen(cd->callerid_name) - 1] = 0;
        } else {
            strlcpy(cd->callerid_number, cd->op->callerid, sizeof(cd->callerid_number));
        }
    } else {
        strlcpy(cd->callerid_number, cd->src, sizeof(cd->callerid_number));
    }

    m2_log(M2_NOTICE, "OP [%d%s], user: [%d%s], balance_from_db: %.4f, tech_prefix: %s, "
        "routing_algorithm: %s, routing_group: [%d%s], tariff: [%d%s], capacity: %d, host: %s, port: %d, src_regexp: %s (%d), src_deny_regexp: %s (%d), "
        "blocked: %d, balance_limit: %.5f, call_limit: %d, time_zone: %s, time_zone_offset: %d, user's datetime: %s %s %s, custom_sip_header: %s, "
        "max_call_timeout: %d, ringing_timeout: %d, callerid_number_pool_id: %d (type: %s), allowed codecs: %s, originator codec list: %s, "
        "dst blacklist/whitelist: %s (list id: %d), src blacklist/whitelist: %s (list id: %d), grace time: %d, failover_1_routing_group: [%d%s], "
        "failover_2_routing_group: [%d%s], allow_calls_from_any_port: %d, custom_tariff_id: %d, device callerid number: %s, device callerid name: %s, "
        "quality_routing_id: %d, op_disable_q850: %d, op_forward_rpid: %d, op_forward_pai: %d, bypass_media: %d, use_invite_dst: %d, inherit_codec: %d, "
        "max_call_rate: %.3f, ring_instead_progress: %d, set_sip_contact: %d, change_rpidpai_host: %d, ignore_183nosdp: %d, fake_ring: %d, "
        "us_jurisdictional_routing: %d (intra: %d, inter: %d, indeter: %d)\n",
        cd->op->id, cd->op->description, cd->op->user_id, cd->op->user_name, cd->op->user_balance, cd->op->tech_prefix, cd->op->routing_algorithm,
        cd->op->routing_group_id, cd->op->routing_group_name, cd->op->tariff_id, cd->op->tariff_name, cd->op->capacity, cd->op->ipaddr, cd->op->port, cd->op->src_regexp, cd->op->src_regexp_status,
        cd->op->src_deny_regexp, cd->op->src_deny_regexp_status, cd->op->user_blocked, cd->op->user_balance_limit, cd->op->user_call_limit,
        cd->op->user_time_zone, cd->op->user_time_zone_offset, cd->op->user_date, cd->op->user_time, cd->op->user_daytype, cd->op->custom_sip_header,
        cd->op->max_timeout, cd->op->ringing_timeout, cd->op->callerid_number_pool_id, cd->op->callerid_number_pool_type, cd->op->allowed_codecs, cd->op->codec_list, cd->op->enable_static_list,
        cd->op->static_list_id, cd->op->enable_static_src_list, cd->op->static_src_list_id, cd->op->grace_time, cd->op->failover_1_routing_group_id, cd->op->failover_1_routing_group_name,
        cd->op->failover_2_routing_group_id, cd->op->failover_2_routing_group_name, cd->op->allow_any_port, cd->op->custom_tariff_id, cd->callerid_number, cd->callerid_name, cd->op->quality_routing_id,
        cd->op->disable_q850, cd->op->forward_rpid, cd->op->forward_pai, cd->op->bypass_media, cd->op->use_invite_dst, cd->op->inherit_codec, cd->op->user_max_call_rate,
        cd->op->ring_instead_progress, cd->op->set_sip_contact, cd->op->change_rpidpai_host, cd->op->ignore_183nosdp, cd->op->fake_ring, cd->op->us_jurisdictional_routing,
        cd->op->tariff_intra_id, cd->op->tariff_inter_id, cd->op->tariff_indeter_id);


    // Handle US Jurisdictional routing
    if (cd->op->us_jurisdictional_routing) {
        if (strlen(cd->rn)) {
            m2_log(M2_NOTICE, "Changing DST number (for routing) from [%s] to RN number [%s] from LNP: %s\n", cd->dst, cd->rn, cd->lnp);
            strcpy(cd->dst, cd->rn);
            cd->rn_number_used = 1;
        }
        m2_us_jurisdictional_routing(cd);
    } else {
        // If US jurisdictional routing is not used
        // then restore tariff to original (from DB) because we might be using cached value where tariff is one of intra/inter/indeter
        cd->op->tariff_id = cd->op->original_tariff_id;
    }


    // enforce global hgc from /etc/m2/system.conf
    if (enforced_global_hgc > 0) {
        m2_log(M2_NOTICE, "Enforce_global_hgc settings is enabled. All failed codes will be changed to %d hgc\n", enforced_global_hgc);
        sprintf(cd->op->hgc_mapping, "-1=%d", enforced_global_hgc);
    }

    // handle 'change all failed codes' situation
    if (inc_hgc == -1 && out_hgc > 0) {
        sprintf(cd->op->hgc_mapping, "-1=%d", out_hgc);
    }

    // should we use destination number from INVITE header?
    if (cd->op->use_invite_dst && strlen(cd->invite_dst)) {
        m2_log(M2_NOTICE, "Changing destination number from TO header (%s) to INVITE request number (%s)\n", cd->dst, cd->invite_dst);
        strcpy(cd->original_dst, cd->invite_dst);
        strcpy(cd->dst, cd->invite_dst);
    }

    if (cd->op->tech_prefix && cd->op->tech_prefix_result) {
        if (strlen(cd->op->tech_prefix)) {
            if (strcmp(cd->op->tech_prefix, cd->op->tech_prefix_result)) {
                m2_log(M2_WARNING, "OP was found by IP but destination number and tech prefix do not match (dst: %s, tech_prefix: %s)\n",
                    cd->dst, cd->op->tech_prefix);
                m2_set_hangupcause(cd, 332);
                return 1;
            }
        }
    }

    if (!cd->op->allow_any_port) {
        if (cd->op->port != cd->op->allowed_port) {
            m2_log(M2_WARNING, "OP was found by IP but port is not allowed (OP port: %d, allowed port: %d)\n",
                cd->op->port, cd->op->allowed_port);
            m2_set_hangupcause(cd, 333);
            return 1;
        }
    }

    if (cd->op->server_id <= 0 && cd->call_tracing == 0 && strlen(proxy_ipaddr) == 0) {
        m2_log(M2_WARNING, "OP is not assigned to the server [%d]!\n", cd->server_id);
        m2_set_hangupcause(cd, 337);
        return 1;
    }

    if (strlen(cd->op->hgc_mapping)) {
        m2_log(M2_NOTICE, "Hangupcause mappings: %s\n", cd->op->hgc_mapping);
    }

    if (callerid_name_ptr) m2_log(M2_NOTICE, "Changing CallerID name to: %s\n", cd->callerid_name);
    if (callerid_number_ptr) m2_log(M2_NOTICE, "Changing CallerID number to: %s\n", cd->callerid_number);

    if (cd->op->callerid_number_pool_id) {
        char new_callerid[100] = "";
        m2_get_callerid_from_number_pool(cd,
                                         new_callerid,
                                         sizeof(new_callerid),
                                         cd->op->callerid_number_pool_id,
                                         cd->op->callerid_number_pool_type,
                                         cd->op->callerid_number_pool_deviation);
        if (strlen(new_callerid)) {
            strlcpy(cd->callerid_number, new_callerid, sizeof(cd->callerid_number));
            strlcpy(cd->callerid_name, new_callerid, sizeof(cd->callerid_name));
        }
    }

    // strip tech prefix from dst
    if (strlen(cd->op->tech_prefix)) {
        if (strncmp(cd->op->tech_prefix, cd->dst, strlen(cd->op->tech_prefix)) == 0) {
            char tmp_dst[100] = "";
            strlcpy(tmp_dst, cd->dst + strlen(cd->op->tech_prefix), sizeof(tmp_dst));
            strlcpy(cd->dst, tmp_dst, sizeof(cd->dst));
            m2_log(M2_NOTICE, "Stripping technical prefix from destination number\n");
            m2_log(M2_NOTICE, "Original destination number: %s, technical prefix: %s, stripped destination number: %s\n",
                cd->original_dst, cd->op->tech_prefix, cd->dst);
        }
    }

    // apply originator destination number transformation rules
    if (strlen(cd->op->dst_transformation)) {
        char number_before_transformation[256] = "";
        strlcpy(number_before_transformation, cd->dst, sizeof(number_before_transformation));
        m2_log(M2_NOTICE, "OP destination transformation: %s\n", cd->op->dst_transformation);
        // check if we have multiple transformation rules
        if (strchr(cd->op->dst_transformation, '|')) {
            // yes, we have multiple
            char *pch;
            char *saveptr;
            char string[256] = "";

            m2_log(M2_DEBUG, "Dst transformation contains multiple transformation rules\n");
            strlcpy(string, cd->op->dst_transformation, sizeof(string));
            pch = strtok_r(string, "|", &saveptr);
            while (pch != NULL) {
                m2_log(M2_NOTICE, "Checking dst transformation rule: %s\n", pch);
                if (tech_prefix_transform(cd->dst, pch)) {
                    m2_log(M2_NOTICE, "Dst transformation rule [%s] was applied, other rules will not be applied\n", pch);
                    break;
                }
                pch = strtok_r(NULL, "|", &saveptr);
            }
        } else {
            // single rule
            tech_prefix_transform(cd->dst, cd->op->dst_transformation);
        }

        m2_log(M2_NOTICE, "Dst before transformation [%s], after [%s]\n", number_before_transformation, cd->dst);
    }

    // apply originator source number transformation rules
    if (strlen(cd->op->src_transformation)) {
        char number_before_transformation[256] = "";
        strlcpy(number_before_transformation, cd->src, sizeof(number_before_transformation));
        m2_log(M2_NOTICE, "OP source transformation: %s\n", cd->op->src_transformation);
        // check if we have multiple transformation rules
        if (strchr(cd->op->src_transformation, '|')) {
            // yes, we have multiple
            char *pch;
            char *saveptr;
            char string[256] = "";

            m2_log(M2_DEBUG, "Source transformation contains multiple transformation rules\n");
            strlcpy(string, cd->op->src_transformation, sizeof(string));
            pch = strtok_r(string, "|", &saveptr);
            while (pch != NULL) {
                m2_log(M2_NOTICE, "Checking source transformation rule: %s\n", pch);
                if (tech_prefix_transform(cd->src, pch)) {
                    m2_log(M2_NOTICE, "Source transformation rule [%s] was applied, other rules will not be applied\n", pch);
                    break;
                }
                pch = strtok_r(NULL, "|", &saveptr);
            }
        } else {
            // single rule
            tech_prefix_transform(cd->src, cd->op->src_transformation);
        }

        m2_log(M2_NOTICE, "Src before transformation [%s], after [%s]\n", number_before_transformation, cd->src);
        strlcpy(cd->callerid_number, cd->src, sizeof(cd->callerid_number));
    }

    if (!auth_by_op_list) {
        m2_mutex_lock(CONNP_LIST_LOCK);
        m2_add_op_to_list(cd);
        m2_mutex_unlock(CONNP_LIST_LOCK);
    }

    return 0;

}



static int m2_authentication_wrapper(calldata_t *cd) {


    meter.m2_authen_count_start++;
    double start_time = m2_get_current_time();

    int res = m2_authentication(cd);

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_authen_time += run_time;
    meter.m2_authen_count++;
    if (run_time > meter.m2_authen_time_max) {
        meter.m2_authen_time_max = run_time;
    }
    if (run_time > meter.m2_authen_time_maxps) {
        meter.m2_authen_time_maxps = run_time;
    }


    return res;

}

/*
    Function compares src vs dst and selects INDETER, INTRA, INTER tariff
*/
static void m2_get_us_jurisdictional_routing_tariff_id(calldata_t *cd, int *tariff_id_to_return, int *case_to_return) {
    int src_len = strlen(cd->src);
    int dst_len = strlen(cd->dst);

    if (!src_len) return;
    if (!dst_len) return;

    // First digit do not match or 1st digit dst is not 1 - indeter tariff
    if ((cd->src[0] != cd->dst[0]) || (cd->dst[0] != '1')) {
        *case_to_return = 1;
        *tariff_id_to_return = cd->op->tariff_indeter_id;
    } else
    // First digit and the following 3 match - intra tariff
    if (strncmp(cd->src, cd->dst, 4) == 0) {
        *case_to_return = 2;
        *tariff_id_to_return = cd->op->tariff_intra_id;
    } else {
        // First digit match but next 3 do not match - intra tariff
        *case_to_return = 3;
        *tariff_id_to_return = cd->op->tariff_inter_id;
    }
}


static void m2_us_jurisdictional_routing(calldata_t *cd) {

    int us_jurisdictional_routing_tariff_id = 0;
    int tariff_case = 0;

    m2_get_us_jurisdictional_routing_tariff_id(cd, &us_jurisdictional_routing_tariff_id, &tariff_case);

    if (us_jurisdictional_routing_tariff_id && tariff_case) {
        // First digits do not match - indeter tariff
        if (tariff_case == 1) {
            m2_log(M2_NOTICE, "Changing tariff_id [%d] to INDETER tariff [%d]: SRC[%s] DST[%s] (1st digit do not match or dst first digit is not 1)\n",
                cd->op->tariff_id, us_jurisdictional_routing_tariff_id, cd->src, cd->dst);
            cd->op->tariff_id = us_jurisdictional_routing_tariff_id;
        } else
        // First digits and the following 3 match - intra tariff
        if (tariff_case == 2) {
            m2_log(M2_NOTICE, "Changing tariff_id [%d] to INTRA tariff [%d]: SRC[%s] DST[%s] (1st digit and the following 3 match)\n",
                cd->op->tariff_id, us_jurisdictional_routing_tariff_id, cd->src, cd->dst);
            cd->op->tariff_id = us_jurisdictional_routing_tariff_id;
        } else
        // First digits match but next 3 do not match - inter tariff
        if (tariff_case == 3) {
            m2_log(M2_NOTICE, "Changing tariff_id [%d] to INTER tariff [%d]: SRC[%s] DST[%s] (1st digit match but the following 3 do not match)\n",
                cd->op->tariff_id, us_jurisdictional_routing_tariff_id, cd->src, cd->dst);
            cd->op->tariff_id = us_jurisdictional_routing_tariff_id;
        }
    }
}
