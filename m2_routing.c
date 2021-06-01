
static int m2_routing(calldata_t *cd) {

    m2_log(M2_NOTICE, "----------------------------------- ROUTING ------------------------------------\n");

    if (cd->tp_count) {
        m2_log(M2_DEBUG, "Generating Routing List\n");
        m2_generate_routing_table(cd, 0);
    }

    if (cd->op->failover_1_routing_group_id && cd->failover_1_tp_count && cd->routing_table_count < max_call_attempts) {
        m2_log(M2_DEBUG, "Generating failover #1 Routing List\n");
        m2_generate_routing_table(cd, 1);
    }

    if (cd->op->failover_2_routing_group_id && cd->failover_2_tp_count && cd->routing_table_count < max_call_attempts) {
        m2_log(M2_DEBUG, "Generating failover #2 Routing List\n");
        m2_generate_routing_table(cd, 2);
    }

    if (cd->routing_table_count) {
        m2_show_routing_table(cd);
        m2_format_dial_string(cd);
    } else {
        return 1;
    }

    if (cd->call_tracing) {
        m2_log(M2_NOTICE, "CALL TRACING IS SUCCESSFUL!\n");
        cd->routing_table_count = 0;
        cd->quiet_call_tracing = 1;
        return 1;
    }

    m2_log(M2_NOTICE, "Dialing TPs...\n");

    // change call state to routing

    if (cd->call_state < M2_RINGING_STATE) m2_change_callstate(cd, M2_RINGING_STATE);

    // Increment active calls
    m2_mutex_lock(COUNTERS_LOCK);
    connp_index[cd->routing_table[0].tpoint->tp_id].out_active_calls++;       // TP active calls
    cd->routing_table[0].tpoint->user->out_active_calls++;                    // User active calls
    cd->routing_table[0].dpeer->global_dp->active_calls++;                    // DP active calls
    m2_mutex_unlock(COUNTERS_LOCK);

    // DP-TP pair active calls
    if (cd->dp_tp_has_limits) {
        dp_tp_t *dp_tp = m2_find_dp_tp(cd, cd->routing_table[0].dpeer->global_dp, cd->routing_table[0].tpoint->tp_id);

        m2_mutex_lock(COUNTERS_LOCK);
        dp_tp->active_calls++;    // Active calls
        m2_set_dp_tp_cps(dp_tp);  // CPS
        m2_mutex_unlock(COUNTERS_LOCK);
    }

    return 0;

}


static int m2_routing_wrapper(calldata_t *cd) {

    meter.m2_rout_count_start++;
    double start_time = m2_get_current_time();

    int res = m2_routing(cd);

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.m2_rout_time += run_time;
    meter.m2_rout_count++;
    if (run_time > meter.m2_rout_time_max) {
        meter.m2_rout_time_max = run_time;
    }
    if (run_time > meter.m2_rout_time_maxps) {
        meter.m2_rout_time_maxps = run_time;
    }

    return res;

}

/*
    Randomize termination points by percent
*/


static void m2_randomize_tp_by_percent(calldata_t *cd, int index, int start_range, int end_range, int failover) {

    dialpeers_t *dpeers = NULL;

    if (failover == 1) {
        dpeers = cd->failover_1_dpeers;
    } else if (failover == 2) {
        dpeers = cd->failover_2_dpeers;
    } else {
        dpeers = cd->dpeers;
    }

    // pointer to termination points in dial peer
    tpoints_t *tpoints_p = dpeers[index].tpoints;

    if (tpoints_p == NULL) {
        return;
    }

    int prev_limit = 0;
    int i = 0;

    dpeers[index].tpoints_rand_count = 0;
    dpeers[index].tpoints_total_percent = 0;

    for (i = 0; i < dpeers[index].tpoints_count; i++) {
        if (tpoints_p[i].randomized == 0) {
            dpeers[index].tpoints_total_percent += tpoints_p[i].tp_percent;
            dpeers[index].tpoints_rand[dpeers[index].tpoints_rand_count].index = i;
            dpeers[index].tpoints_rand[dpeers[index].tpoints_rand_count].min = prev_limit;
            dpeers[index].tpoints_rand[dpeers[index].tpoints_rand_count].max = prev_limit + tpoints_p[i].tp_percent;
            prev_limit = prev_limit + tpoints_p[i].tp_percent;
            dpeers[index].tpoints_rand_count++;
        }
    }

    m2_log(M2_DEBUG, "Total percent: %d\n", dpeers[index].tpoints_total_percent);

}


/*
    Sort routing table
*/


static void m2_sort_routing_table(calldata_t *cd, int range_start, int range_end, int sort_by, int failover, routing_table_t *routing_table) {

    // sort_by 0 - sort by tp price ASC
    // sort_by 1 - sort by tp weight ASC (op routing algorithm)
    // sort_by 2 - sort by tp percent ASC (op routing algorithm)
    // sort_by 3 - sort by tp weight ASC (dp routing algorithm)
    // sort_by 4 - sort by tp percent ASC (dp routing algorithm)
    // sort_by 5 - sort by tp quality (dp routing algorithm)

    int done = 0;

    routing_table_t routing_table_tmp;

    if (sort_by == 0) {
        m2_log(M2_DEBUG, "Sorting TPs in DP [%d] by PRICE (sorting range start: %d, range end: %d)\n", routing_table[range_start].dpeer->id, range_start + 1, range_end);
    } else if (sort_by == 1 || sort_by == 3) {
        m2_log(M2_DEBUG, "Sorting TPs in DP [%d] by WEIGHT (sorting range start: %d, range end: %d)\n", routing_table[range_start].dpeer->id, range_start + 1, range_end);
    } else if (sort_by == 2 || sort_by == 4) {
        m2_log(M2_DEBUG, "Sorting TPs in DP [%d] by PERCENT (sorting range start: %d, range end: %d)\n", routing_table[range_start].dpeer->id, range_start + 1, range_end);
    } else if (sort_by == 5) {
        m2_log(M2_DEBUG, "Sorting TPs in DP [%d] by QUALITY (sorting range start: %d, range end: %d)\n", routing_table[range_start].dpeer->id, range_start + 1, range_end);
    }

    do {

        int i = 0;
        done = 1;

        for (i = range_start; i < range_end - 1; i++) {

            // by default sort by dial peer priority
            double check_1 = 0;
            double check_2 = 0;

            if (sort_by == 0) {
                check_1 = routing_table[i].tp_price;
                check_2 = routing_table[i + 1].tp_price;
            } else if (sort_by == 1 || sort_by == 3) {
                check_1 = routing_table[i].tp_weight;
                check_2 = routing_table[i + 1].tp_weight;
            } else if (sort_by == 2 || sort_by == 4) {
                check_1 = routing_table[i].tp_percent_index;
                check_2 = routing_table[i + 1].tp_percent_index;
            } else if (sort_by == 5) {
                check_1 = routing_table[i].tp_quality_index;
                check_2 = routing_table[i + 1].tp_quality_index;
            }

            if (sort_by == 5) {
                if (check_1 < check_2) {
                    memcpy(&routing_table_tmp, &routing_table[i], sizeof(routing_table_t));
                    memcpy(&routing_table[i], &routing_table[i + 1], sizeof(routing_table_t));
                    memcpy(&routing_table[i + 1], &routing_table_tmp, sizeof(routing_table_t));
                    done = 0;
                }
            } else {
                if (check_1 > check_2) {
                    memcpy(&routing_table_tmp, &routing_table[i], sizeof(routing_table_t));
                    memcpy(&routing_table[i], &routing_table[i + 1], sizeof(routing_table_t));
                    memcpy(&routing_table[i + 1], &routing_table_tmp, sizeof(routing_table_t));
                    done = 0;
                }
            }

        }

    } while (done == 0);

}


/*
    Sort termination points in each dial peer
*/


static void m2_sort_tp_in_dialpeers(calldata_t *cd, routing_table_t *routing_table, int algorithm, int failover, int routing_table_count) {

    // go through every record and find distinct dial peers
    // and sort termination points only for these dial peers
    // this means we need to find ranges where dial peer X starts and ends
    // because dial peers are sorted by id, it is easy to do so
    // just check one by one and if previous id differs from current id
    // then we reached another dial peer

    int i = 0;
    int index = routing_table_count;
    int range_start = 0;
    int range_end = 0;
    int dp_id = routing_table[0].dpeer->id;
    int prev_dp_id = dp_id;
    int sort_by = 0;
    char tp_priority[32] = "";

    // initial tp_priority value
    if (algorithm == 2) {
        strcpy(tp_priority, routing_table[0].dpeer->secondary_tp_priority);
    } else {
        strcpy(tp_priority, routing_table[0].dpeer->tp_priority);
    }

    // if algorithm 2, then use secondary dial peer sorting algorithm
    // if algorithm 1, then use origination point sorting algorithm
    // if algorithm 0, then use primary dial peer sorting algorithm

    if (algorithm == 1) {
        if (strcmp(cd->op->routing_algorithm, "weight") == 0) {
            sort_by = 1;
        } else if (strcmp(cd->op->routing_algorithm, "percent") == 0) {
            sort_by = 2;
        } else if (strcmp(cd->op->routing_algorithm, "quality") == 0) {
            sort_by = 5;
        }
    }

    for (i = 0; i < index; i++) {
        dp_id = routing_table[i].dpeer->id;

        // sort when another dial peer is found
        if (dp_id != prev_dp_id) {

            if (algorithm == 2) {
                strcpy(tp_priority, routing_table[range_start].dpeer->secondary_tp_priority);
            } else {
                strcpy(tp_priority, routing_table[range_start].dpeer->tp_priority);
            }

            if (algorithm == 0 || algorithm == 2) {
                if (strcmp(tp_priority, "weight") == 0) {
                    sort_by = 3;
                } else if (strcmp(tp_priority, "percent") == 0) {
                    sort_by = 4;
                } else if (strcmp(tp_priority, "price") == 0) {
                    sort_by = 0;
                }
            }

            range_end = i;
            // only sort if there are more than 1 tp in dial peer
            if ((range_end - range_start) > 1) {
                // if sorting is by weight, then also sort by random index
                // in case two termination points have the same weight
                if (strlen(tp_priority) && strcmp(tp_priority, "none") != 0) {
                    m2_sort_routing_table(cd, range_start, range_end, sort_by, failover, routing_table);
                }
            }
            range_start = i;
        }
        prev_dp_id = dp_id;
    }

    // because every time we were sorting previous dial peers
    // don't forget to sort the last dial peer
    // only sort if there are more than 1 tp in dial peer

    if ((index - range_start) > 1) {
        if (algorithm == 0 || algorithm == 2) {
            if (strcmp(tp_priority, "weight") == 0) {
                sort_by = 3;
            } else if (strcmp(tp_priority, "percent") == 0) {
                sort_by = 4;
            } else if (strcmp(tp_priority, "price") == 0) {
                sort_by = 0;
            }
        }

        if (strlen(tp_priority) && strcmp(tp_priority, "none") != 0) {
            m2_sort_routing_table(cd, range_start, index, sort_by, failover, routing_table);
        }
    }

}


/*
    Get probability indexes for termination points
*/


static int m2_get_tp_by_percent(calldata_t *cd, int index, int failover) {

    dialpeers_t *dpeers = NULL;

    if (failover == 1) {
        dpeers = cd->failover_1_dpeers;
    } else if (failover == 2) {
        dpeers = cd->failover_2_dpeers;
    } else {
        dpeers = cd->dpeers;
    }

    // security
    if (!&dpeers[index]) return 0;
    if (!&dpeers[index].tpoints_rand) return 0;

    // pointer to termination points random table in dial peer
    tpoints_rand_t *tpoints_rand_p = dpeers[index].tpoints_rand;

    // pointer to termination points count in dial peer
    int *tpoints_rand_c = &dpeers[index].tpoints_rand_count;

    if (dpeers[index].tpoints_total_percent == 0) {
        dpeers[index].tpoints_total_percent = 1;
    }

    int rng = random() % dpeers[index].tpoints_total_percent + 1;
    int i = 0;

    m2_log(M2_DEBUG, "Random number: %d\n", rng);

    for (i = 0; i < *tpoints_rand_c; i++) {

        if (rng > tpoints_rand_p[i].min && rng <= tpoints_rand_p[i].max) {
            m2_log(M2_DEBUG, "Index: %d, min: %d, max: %d\n", tpoints_rand_p[i].index, tpoints_rand_p[i].min, tpoints_rand_p[i].max);
            dpeers[index].tpoints[tpoints_rand_p[i].index].randomized = 1;
            return tpoints_rand_p[i].index;
        }

    }

    return 0;

}

static void m2_generate_routing_table(calldata_t *cd, int failover) {

    int i = 0;
    int j = 0;
    int local_routing_table_count = 0;
    routing_table_t *local_routing_table = NULL;
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

    for (i = 0; i < dpeers_count; i++) {
        // distribute termination points by percent
        if (strcmp(cd->op->routing_algorithm, "percent") == 0 || strcmp(dpeers[i].tp_priority, "percent") == 0 || strcmp(dpeers[i].secondary_tp_priority, "percent") == 0) {
            m2_log(M2_DEBUG, "Generating random indexes for TPs in DP [%d]\n", dpeers[i].id);
            for (j = 0; j < dpeers[i].tpoints_count; j++) {
                m2_randomize_tp_by_percent(cd, i, 0, dpeers[i].tpoints_count, failover);
                int percent_index = m2_get_tp_by_percent(cd, i, failover);
                if (percent_index < dpeers[i].tpoints_count && percent_index >= 0) {
                    dpeers[i].tpoints[percent_index].tp_percent_index = j;
                }
            }
        }
    }

    // default routing table
    for (i = 0; i < dpeers_count; i++) {
        for (j = 0; j < dpeers[i].tpoints_count; j++) {
            local_routing_table = realloc(local_routing_table, (local_routing_table_count + 1) * sizeof(routing_table_t));
            memset(&local_routing_table[local_routing_table_count], 0, sizeof(routing_table_t));
            local_routing_table[local_routing_table_count].dpeer = &dpeers[i];
            local_routing_table[local_routing_table_count].tpoint = &dpeers[i].tpoints[j];
            local_routing_table[local_routing_table_count].tp_percent = dpeers[i].tpoints[j].tp_percent;
            local_routing_table[local_routing_table_count].tp_percent_index = dpeers[i].tpoints[j].tp_percent_index;
            local_routing_table[local_routing_table_count].tp_weight = dpeers[i].tpoints[j].tp_weight;
            local_routing_table[local_routing_table_count].tp_price = dpeers[i].tpoints[j].tp_rate_after_exchange;
            local_routing_table[local_routing_table_count].tp_quality_index = 0;
            local_routing_table_count++;
        }
    }

    // initialize data for quality routing
    for (i = 0; i < local_routing_table_count; i++) {
        m2_initialize_quality_data(cd, local_routing_table[i].dpeer->id, local_routing_table[i].tpoint->tp_id);
    }

    // set quality index for each terminator
    if (local_routing_table_count > 1 && strcmp(cd->op->routing_algorithm, "quality") == 0) {
        // get data
        m2_get_quality_data(cd);
        // we are working with global variables, let's lock
        m2_mutex_lock(QUALITY_TABLE_LOCK);
        for (i = 0; i < local_routing_table_count; i++) {
            local_routing_table[i].tp_quality_index = m2_calculate_quality_index(cd, local_routing_table[i].dpeer->id, local_routing_table[i].tpoint->tp_id, local_routing_table[i].tp_price, local_routing_table[i].tp_weight, local_routing_table[i].tp_percent, NULL);
        }
        // don't forget to unlock
        m2_mutex_unlock(QUALITY_TABLE_LOCK);
    }

    // SORT TERMINATION POINTS IN DIAL PEER (by dial peer routing algorithm)
    // only when we have atleast 2 records in routing table
    // also, do not sort by dial peer routing algorithm if op routing algorithm is by percent, because in this case
    // there should't be any termination point with the same tp_percent_index

    if (local_routing_table_count > 1 && strcmp(cd->op->routing_algorithm, "percent") != 0) {
        // secondary tp priority in DP
        m2_sort_tp_in_dialpeers(cd, local_routing_table, 2, failover, local_routing_table_count);
        // primary tp priority in DP
        m2_sort_tp_in_dialpeers(cd, local_routing_table, 0, failover, local_routing_table_count);
    }

    // SORT TERMINATION POINTS IN DIAL PEER (by op routing algorithm)
    // only when we have atleast 2 records in routing table
    // skip this sorting if OP routing algorithm is by dial peer, because sorting by dial peer is already done above

    if (local_routing_table_count > 1 && strcmp(cd->op->routing_algorithm, "by_dialpeer") != 0) {
        m2_sort_tp_in_dialpeers(cd, local_routing_table, 1, failover, local_routing_table_count);
    }

    // add local routing table to final routing table
    if (local_routing_table_count) {

        int dpi = 0;
        int last_dp_id = 0;
        int no_follow_detected = 0;

        // handle 'no follow' feature
        // use only first tp in dial peer, where no follow is enabled
        // no follow is handled here, because we need to have sorted termination points in dial peer
        // use only FIRST SORTED tp in dial peer

        for (i = 0; i < local_routing_table_count; i++) {

            dpi = local_routing_table[i].dpeer->id;

            // every time we get new dial peer, reset 'no_follow_detected'
            if (dpi != last_dp_id) {
                no_follow_detected = 0;
            }
            last_dp_id = dpi;

            // add data from local routing group to final routing table
            if (no_follow_detected == 0) {

                // check if current tp is not included already
                int already_included = 0;
                for (j = 0; j < cd->routing_table_count; j++) {
                    if (cd->routing_table[j].tpoint->tp_id == local_routing_table[i].tpoint->tp_id) {
                        m2_log(M2_DEBUG, "TP [%d] is already included in the Routing List\n", local_routing_table[i].tpoint->tp_id);
                        already_included = 1;
                    }
                }

                if (already_included == 0) {
                    cd->routing_table = realloc(cd->routing_table, (cd->routing_table_count + 1) * sizeof(routing_table_t));
                    memset(&cd->routing_table[cd->routing_table_count], 0, sizeof(routing_table_t));
                    cd->routing_table[cd->routing_table_count].dpeer = local_routing_table[i].dpeer;
                    cd->routing_table[cd->routing_table_count].tpoint = local_routing_table[i].tpoint;
                    cd->routing_table[cd->routing_table_count].tp_weight = local_routing_table[i].tp_weight;
                    cd->routing_table[cd->routing_table_count].tp_percent_index = local_routing_table[i].tp_percent_index;
                    cd->routing_table[cd->routing_table_count].tp_quality_index = local_routing_table[i].tp_quality_index;
                    cd->routing_table[cd->routing_table_count].tp_price = local_routing_table[i].tp_price;
                    cd->routing_table[cd->routing_table_count].failover = failover;
                    cd->routing_table_count++;
                    if (cd->routing_table_count == max_call_attempts) {
                        m2_log(M2_WARNING, "Maximum number of dial attempts [%d] is reached. Skipping other TPs\n", max_call_attempts);
                        goto max_call_attempts_limit_reached;
                    }
                }
            }

            if (local_routing_table[i].dpeer->no_follow) {
                if (no_follow_detected == 0) {
                    m2_log(M2_DEBUG, "No follow is enabled in DP [%d], skipping other TPs in this DP\n", local_routing_table[i].dpeer->id);
                    no_follow_detected = 1;
                }
            }

        }

    }

    max_call_attempts_limit_reached:

    if (local_routing_table) {
        free(local_routing_table);
        local_routing_table = NULL;
    }

}


static int m2_handle_call_end(calldata_t *cd, REQUEST *radius_acctstop_request) {

    int billsec = 0;
    char billsec_string[60] = "";
    char freeswitch_hgc_string[60] = "";
    char freeswitch_pdd_string[60] = "";
    char freeswitch_pdd_media_string[60] = "";
    char originator_codec_used[60] = "";
    char terminator_codec_used[60] = "";
    char endpoint_disposition[60] = "";
    char leg_b_sip_hangupcause_str[60] = "";
    char leg_a_sip_hangupcause_str[60] = "";
    char freeswitch_hgc[60] = "";
    char created_at_str[60] = "";
    char answered_at_str[60] = "";
    char hangup_at_str[60] = "";
    char hangup_disp[60] = "";
    int freeswitch_hgc_integer = 0;
    int freeswitch_pdd = 0;
    int freeswitch_pdd_media = 0;
    int leg_a_sip_hangupcause = 0;
    int leg_b_sip_hangupcause = 0;
    double created_at = 0;
    double answered_at = 0;
    double hangup_at = 0;
    float pdd = 0;

    // Standard radius attributes
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "Acct-Session-Time", billsec_string, sizeof(billsec_string), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "h323-disconnect-cause", freeswitch_hgc, sizeof(freeswitch_hgc), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "h323-setup-time", created_at_str, sizeof(created_at_str), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "h323-connect-time", answered_at_str, sizeof(answered_at_str), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "h323-disconnect-time", hangup_at_str, sizeof(hangup_at_str), M2_STANDARD_AVP);

    // Custom radius attributes
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-hangupcause", freeswitch_hgc_string, sizeof(freeswitch_hgc_string), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-pdd", freeswitch_pdd_string, sizeof(freeswitch_pdd_string), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-media-pdd", freeswitch_pdd_media_string, sizeof(freeswitch_pdd_media_string), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "terminator-sip-hangupcause", leg_b_sip_hangupcause_str, sizeof(leg_b_sip_hangupcause_str), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "originator-sip-hangupcause", leg_a_sip_hangupcause_str, sizeof(leg_a_sip_hangupcause_str), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-hangup-disp", hangup_disp, sizeof(hangup_disp), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-op-codec", originator_codec_used, sizeof(originator_codec_used), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-tp-codec", terminator_codec_used, sizeof(terminator_codec_used), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(radius_acctstop_request, "freeswitch-endpnt-disp", endpoint_disposition, sizeof(endpoint_disposition), M2_CISCO_AVP);

    if (strlen(billsec_string)) billsec = atoi(billsec_string);
    if (strlen(freeswitch_hgc_string)) freeswitch_hgc_integer = atoi(freeswitch_hgc_string);
    if (strlen(freeswitch_pdd_string)) freeswitch_pdd = atoi(freeswitch_pdd_string);
    if (strlen(freeswitch_pdd_media_string)) freeswitch_pdd_media = atoi(freeswitch_pdd_media_string);

    m2_set_codec_nice_names(cd->originator_codec_used, originator_codec_used);
    m2_set_codec_nice_names(cd->terminator_codec_used, terminator_codec_used);

    if (strlen(leg_a_sip_hangupcause_str)) {
        leg_a_sip_hangupcause = atoi(leg_a_sip_hangupcause_str + strlen("sip:"));
    }

    if (strlen(leg_b_sip_hangupcause_str)) {
        leg_b_sip_hangupcause = atoi(leg_b_sip_hangupcause_str + strlen("sip:"));
    }

    if (strlen(hangup_disp)) {
        if (strcmp(hangup_disp, "recv_bye") == 0 || strcmp(hangup_disp, "recv_refuse") == 0) {
            strcpy(cd->hangup_by, "terminator");
        } else if (strcmp(hangup_disp, "send_bye") == 0 || strcmp(hangup_disp, "send_cancel") == 0) {
            strcpy(cd->hangup_by, "system");
        }
    }

    if (cd->system_hangup_reason > M2_SYSTEM_HANGUP_NOT_REQUESTED) {
        strcpy(cd->hangup_by, "system");
    }

    // pdd INVITE -> SIP 180
    if (freeswitch_pdd > 0) {
        pdd = freeswitch_pdd;
    }

    // pdd INVITE -> SIP 183
    if (freeswitch_pdd_media > 0) {
        // update pdd only if we received SIP 183 before SIP 180
        // or if we didn't get SIP 180 at all
        if (freeswitch_pdd_media < pdd || pdd == 0) {
            pdd = freeswitch_pdd_media;
        }
    }

    // calculate pdd decimal value
    pdd = pdd / 1000.0;

    // default dialstatus
    strlcpy(cd->dialstatus, "FAILED", sizeof(cd->dialstatus));
    if (freeswitch_hgc_integer) {
        if (freeswitch_hgc_integer == 17 || strcmp(freeswitch_hgc, "USER_BUSY") == 0) {
            strlcpy(cd->dialstatus, "BUSY", sizeof(cd->dialstatus));
        } else if (freeswitch_hgc_integer == 19 || freeswitch_hgc_integer == 487 || freeswitch_hgc_integer == 18) {
            strlcpy(cd->dialstatus, "NO ANSWER", sizeof(cd->dialstatus));
        }

        cd->hangupcause = freeswitch_hgc_integer;
    }

    if (cd->call_state == M2_ANSWERED_STATE) {
        strlcpy(cd->dialstatus, "ANSWERED", sizeof(cd->dialstatus));
        if (strcmp(hangup_disp, "recv_bye") == 0) {
            strcpy(cd->hangup_by, "terminator");
        } else if (freeswitch_hgc_integer != 604) {
            strcpy(cd->hangup_by, "originator");
        }
    }

    // in case of media timeout, set hgc to 16 (in all stats pages, answered call is determined by 16 hgc)
    if (freeswitch_hgc_integer == 604 && cd->call_state == M2_ANSWERED_STATE) {
        cd->hangupcause = 16;
    }

    created_at = m2_get_time(created_at_str);
    answered_at = m2_get_time(answered_at_str);
    hangup_at = m2_get_time(hangup_at_str);

    // If call was terminated by the system, get create, answer and end dates from other source
    // because we will not be handling acct stop request from freeswitch
    if (cd->system_hangup_reason) {
        struct timeb tp;
        ftime(&tp);

        created_at = cd->start_time;
        answered_at = cd->answer_time;
        hangup_at = tp.time + (tp.millitm / 1000.0);
        strcpy(cd->hangup_by, "system");
    }

    // in some cases we don't get answered time from freeswitch
    // this happens if call is hangup very shortly after answer
    // to bill this call, we will take created time as answer time
    if (answered_at < created_at) {
        if (freeswitch_hgc_integer == 16) {
            answered_at = created_at;
        }
    }

    m2_log(M2_NOTICE, "Start time: %f, answer time: %f, end time: %f, billsec: %d, pdd: %.3f, op codec: %s, tp codec: %s\n",
        created_at, answered_at, hangup_at, billsec, pdd, cd->originator_codec_used, cd->terminator_codec_used);

    cd->real_duration = hangup_at - created_at;

    if (billsec_round_function == 0) {                  // ceilf
        cd->duration = ceilf(hangup_at - created_at);
    } else if (billsec_round_function == 1) {           // roundf
        cd->duration = roundf(hangup_at - created_at);
    } else if (billsec_round_function == 2) {           // floorf
        cd->duration = floorf(hangup_at - created_at);
    } else {                                            // none of the above? use ceilf
        cd->duration = ceilf(hangup_at - created_at);
    }

    if (answered_at) {
        cd->real_billsec = hangup_at - answered_at;

        if (billsec_round_function == 0) {                  // ceilf
            cd->billsec = ceilf(hangup_at - answered_at);
        } else if (billsec_round_function == 1) {           // roundf
            cd->billsec = roundf(hangup_at - answered_at);
        } else if (billsec_round_function == 2) {           // floorf
            cd->billsec = floorf(hangup_at - answered_at);
        } else {                                            // none of the above? use ceilf
            cd->billsec = ceilf(hangup_at - answered_at);
        }

    } else {
        cd->real_billsec = 0;
        cd->billsec = 0;
    }

    // if hangupcause was not set (-1) then set UNSPECIFIED
    if (cd->hangupcause == -1) {
        cd->hangupcause = 0;
    }

    if (freeswitch_hgc_integer == 487) {
        cd->hangupcause = 312;
        strcpy(cd->hangup_by, "originator");
        strlcpy(cd->dialstatus, "NO ANSWER", sizeof(cd->dialstatus));
        // sometimes CANCELLED request may have duration of 0.x seconds due to SIP 200 OK response coming just after originator cancelled call
        // in this case set disposition to ANSWERED
        if (cd->billsec > 0) {
            m2_log(M2_NOTICE, "OP cancelled call just before TP. Disposition will be set to ANSWERED!\n");
            cd->hangupcause = 16;
            strcpy(cd->dialstatus, "ANSWERED");
            cd->call_state = M2_ANSWERED_STATE;
        }
    }

    if (freeswitch_hgc_integer == 0 && strcmp(freeswitch_hgc, "SUBSCRIBER_ABSENT") == 0) {
        cd->hangupcause = 316;
    }

    if (freeswitch_hgc_integer == 0 && strcmp(freeswitch_hgc, "GATEWAY_DOWN") == 0) {
        cd->hangupcause = 317;
    }

    if (freeswitch_hgc_integer == 0 && strcmp(freeswitch_hgc, "EXCHANGE_ROUTING_ERROR") == 0) {
        cd->hangupcause = 343;
        cd->end_call = 1;
    }

    // do not bill INCOMPATIBLE_DESTINATION calls
    if (freeswitch_hgc_integer == 88 && cd->billsec < 3) {
        strcpy(cd->dialstatus, "FAILED");
        cd->billsec = 0;
        cd->real_billsec = 0;
        if (cd->call_state == M2_ANSWERED_STATE) {
            cd->end_call = 1;
        }
    }


    if (cd->call_state >= M2_ROUTING_STATE && cd->call_tracing == 0 && cd->routing_table_count) {
        // set pdd for this tp
        cd->routing_table[cd->dial_count].tpoint->pdd = pdd;

        strcpy(cd->routing_table[cd->dial_count].tpoint->answer_time, answered_at_str);
        cd->routing_table[cd->dial_count].tpoint->answer_time[10] = ' ';

        strcpy(cd->routing_table[cd->dial_count].tpoint->end_time, hangup_at_str);
        cd->routing_table[cd->dial_count].tpoint->end_time[10] = ' ';

        m2_log(M2_NOTICE, "TP [%d%s], received dialstatus: %s, cd->dialstatus: %s, received hangupcause: %d, cd->hangupcause: %d, OP channel name: %s, legA sip code: %d, legB sip code: %d, FS hangup by: %s\n",
        cd->routing_table[cd->dial_count].tpoint->tp_id, cd->routing_table[cd->dial_count].tpoint->tp_description, freeswitch_hgc, cd->dialstatus, freeswitch_hgc_integer, cd->hangupcause, cd->chan_name, leg_a_sip_hangupcause, leg_b_sip_hangupcause, hangup_disp);
    } else {
        m2_log(M2_NOTICE, "Received dialstatus: %s, cd->dialstatus: %s, received hangupcause: %d, cd->hangupcause: %d, OP channel name: %s, legA sip code: %d, fs hangup by: %s\n",
        freeswitch_hgc, cd->dialstatus, freeswitch_hgc_integer, cd->hangupcause, cd->chan_name, leg_a_sip_hangupcause, hangup_disp);
    }

    // possible error fix
    if (cd->real_duration < 0) cd->real_duration = 1;
    if (cd->real_billsec < 0) cd->real_billsec = 0;
    if (cd->duration < 0) cd->duration = 1;
    if (cd->billsec < 0) cd->billsec = 0;
    if (!cd->duration) cd->billsec = 0;

    m2_log(M2_NOTICE, "Real Duration: %f, Real Billsec: %f, Duration: %d, Billsec: %d\n", cd->real_duration, cd->real_billsec, cd->duration, cd->billsec);

    // when should we end call?
    if (strcmp(cd->dialstatus, "ANSWERED") == 0) cd->end_call = 1;      // answered calls
    if (strcmp(cd->dialstatus, "BUSY") == 0) cd->end_call = 1;          // busy calls
    if (strcmp(cd->dialstatus, "NO ANSWER") == 0) {                     // not answered calls
        cd->end_call = 1;
    }
    if (cd->hangupcause == 312) cd->end_call = 1;                       // caller canceled the call
    if (cd->system_hangup_reason) cd->end_call = 1;                     // hangup requested by the system

    if (cd->hangupcause >= 300 && cd->hangupcause < 400 && cd->hangupcause != 312) {
        strcpy(cd->hangup_by, "system");
    }

    // System error
    if (cd->hangupcause == 500) {
        cd->end_call = 1;
        strcpy(cd->hangup_by, "system");
    }

    // handle interpret no answer as failed
    if (cd->hangupcause != 312 && strcmp(cd->dialstatus, "NO ANSWER") == 0 && cd->routing_table_count && cd->routing_table[cd->dial_count].tpoint->tp_interpret_noanswer_as_failed == 1) {
        m2_log(M2_NOTICE, "Got dial status NO ANSWER, but interpret NO ANSWER as FAILED is enabled in TP %d\n", cd->routing_table[cd->dial_count].tpoint->tp_id);
        cd->end_call = 0;
    }

    // handle interpret busy as failed
    if (strcmp(cd->dialstatus, "BUSY") == 0 && cd->routing_table_count && cd->routing_table[cd->dial_count].tpoint->tp_interpret_busy_as_failed == 1) {
        m2_log(M2_NOTICE, "Got dial status BUSY, but interpret BUSY as FAILED is enabled in TP %d\n", cd->routing_table[cd->dial_count].tpoint->tp_id);
        cd->end_call = 0;
    }

    // check if bypass_media is enabled and we got EARLY MEDIA from this terminator
    if (cd->end_call == 0 && cd->bypass_early_media == 1 && (cd->routing_table[cd->dial_count].tpoint->tp_bypass_media || cd->op->bypass_media)) {
        m2_log(M2_NOTICE, "Bypass media is enabled and EARLY MEDIA received from TP. Skipping other routes.\n");
        cd->end_call = 1;
    }

    // special case for CODEC NEGOTIATION ERROR #13413
    // Freeswitch cannot handle legA codec so do not dial other terminators
    if (strcmp(freeswitch_hgc, "INCOMPATIBLE_DESTINATION") == 0 && strcmp(endpoint_disposition, "CODEC_NEGOTIATION_ERROR") == 0) {
        m2_log(M2_WARNING, "OP codec negotiation error, skipping other TPs!\n");
        cd->end_call = 1;
    }

    // billing logic fix for CRM #32851
    // sometimes providers return SIP 500 (or any other SIP code) and includes Reason header with NORMAL_CLEARING (16)
    // freeswitch handles this call as anwered but in reality it was not answered
    if (freeswitch_hgc_integer == 16 && strcmp(freeswitch_hgc, "NORMAL_CLEARING") == 0 && cd->call_state != M2_ANSWERED_STATE) {
        // Handle only if SIP code is 200 (answered) or unknown
        if (leg_b_sip_hangupcause == 200 || leg_b_sip_hangupcause == 0) {
            m2_log(M2_WARNING, "Hangupcause is NORMAL_CLEARING(16) but answer event was not trigerred!\n");
            if (!m2_get_time(answered_at_str)) {
                m2_log(M2_WARNING, "Call will not be billed!\n");
                strlcpy(cd->dialstatus, "FAILED", sizeof(cd->dialstatus));
                cd->billsec = 0;
                cd->real_billsec = 0;
                if (change_failed_16_to > 0 && change_failed_16_to < 400) {
                    m2_log(M2_NOTICE, "Changing hangupcause 16 to %d\n", change_failed_16_to);
                    cd->hangupcause = change_failed_16_to;
                }
            } else {
                strcpy(cd->dialstatus, "ANSWERED");
                cd->call_state = M2_ANSWERED_STATE;
                cd->end_call = 1;
            }
        } else {
            m2_log(M2_DEBUG, "Hangupcause NORMAL_CLEARING(16) but SIP code is: %d, call disposition will be set to FAILED\n", leg_b_sip_hangupcause);
            strlcpy(cd->dialstatus, "FAILED", sizeof(cd->dialstatus));
            cd->billsec = 0;
            cd->real_billsec = 0;
        }
    }

    // check maybe call should not be rerouted
    if (strlen(reroute_stop_hgc)) {
        char stop_hgc_buffer[256] = "";
        char hgc_buffer[256] = "";

        sprintf(stop_hgc_buffer, ",%s,", reroute_stop_hgc);
        sprintf(hgc_buffer, ",%d,", freeswitch_hgc_integer);

        if (strstr(stop_hgc_buffer, hgc_buffer)) {
            m2_log(M2_NOTICE, "Hangupcause %d should not be rerouted to other TPs! Reroute stop HGC list: %s\n", freeswitch_hgc_integer, reroute_stop_hgc);
            cd->end_call = 1;
        }
    }

    // update quality table
    if (!disable_advanced_routing) {
        if (cd->call_state >= M2_ROUTING_STATE && cd->call_tracing == 0 && cd->routing_table_count) {
            m2_log(M2_NOTICE, "Updating Quality Table\n");
            m2_update_quality_table(cd, cd->routing_table[cd->dial_count].dpeer->id, cd->routing_table[cd->dial_count].tpoint->tp_id, cd->billsec, strcmp(cd->dialstatus, "ANSWERED") == 0 ? 1 : 0, cd->timestamp, 1);
        }
    }

    // Decrement TP active call count for current TP
    if (cd->routing_table_count) {
        m2_mutex_lock(COUNTERS_LOCK);
        cd->routing_table[cd->dial_count].dpeer->global_dp->active_calls--;
        cd->routing_table[cd->dial_count].tpoint->user->out_active_calls--;
        connp_index[cd->routing_table[cd->dial_count].tpoint->tp_id].out_active_calls--;
        m2_mutex_unlock(COUNTERS_LOCK);

        // Find DP-TP pair
        if (cd->dp_tp_has_limits) {
            dp_tp_t *dp_tp = m2_find_dp_tp(cd, cd->routing_table[cd->dial_count].dpeer->global_dp, cd->routing_table[cd->dial_count].tpoint->tp_id);

            m2_mutex_lock(COUNTERS_LOCK);
            dp_tp->active_calls--;    // Active calls
            m2_set_dp_tp_cps(dp_tp);  // CPS
            m2_mutex_unlock(COUNTERS_LOCK);
        }

    }

    cd->dial_count++;

    // Increment TP active call count for next TP
    if (!cd->end_call && cd->routing_table_count && cd->dial_count < cd->routing_table_count) {
        m2_mutex_lock(COUNTERS_LOCK);
        connp_index[cd->routing_table[cd->dial_count].tpoint->tp_id].out_active_calls++;
        cd->routing_table[cd->dial_count].tpoint->user->out_active_calls++;
        cd->routing_table[cd->dial_count].dpeer->global_dp->active_calls++;
        m2_mutex_unlock(COUNTERS_LOCK);

        // Find DP-TP pair
        if (cd->dp_tp_has_limits) {
            dp_tp_t *dp_tp = m2_find_dp_tp(cd, cd->routing_table[cd->dial_count].dpeer->global_dp, cd->routing_table[cd->dial_count].tpoint->tp_id);

            m2_mutex_lock(COUNTERS_LOCK);
            dp_tp->active_calls++;         // Active calls
            m2_set_dp_tp_cps(dp_tp);       // CPS
            m2_mutex_unlock(COUNTERS_LOCK);
        }
    }

    if (cd->dial_count > cd->routing_table_count) {
        cd->dial_count = cd->routing_table_count;
    }

    // log only failed CDR (but skip last attempt, it will be included in main cdr)
    if (!cd->end_call && cd->dial_count < cd->routing_table_count) {
        m2_log_cdr(cd, 0);
    }

    // dialed all terminators
    if (cd->dial_count >= cd->routing_table_count) {
        cd->end_call = 1;
    }

    return 0;

}


/*
    Transform number by tech prefix rules
*/


static int tech_prefix_transform(char *dst_arg, char *tech_prefix_arg) {

    char tech_prefix[256] = "";
    char dst[256] = "";
    char tmp[256] = "";
    int escape = 0;

    strlcpy(dst, dst_arg, sizeof(dst));
    strlcpy(tech_prefix, tech_prefix_arg, sizeof(tech_prefix));

    // only one symbol so there can not be any complex transformations
    if (strlen(tech_prefix) == 1) {
        sprintf(tmp, "%s%s", tech_prefix, dst);
        strcpy(dst_arg, tmp);
        return 1;
    }

    // check first symbol
    if (tech_prefix[0] == '-') {

        int i = 1, j = 0;
        char tmp_cut[256] = "";
        char tmp_add[256] = "";

        // now get all the symbols until end of string or until symbol +
        while ((tech_prefix[i] != '+' || escape != 0) && tech_prefix[i] != 0 && i < (sizeof(tech_prefix) - 3)) {
            escape = 0;
            if (tech_prefix[i] == '\\') {
                escape = 1;
            } else {
                tmp_cut[j] = tech_prefix[i];
                j++;
            }
            i++;
        }

        // do we have something to add?
        if (tech_prefix[i] == '+') {
            // are the more symbols after + ?
            if (&tech_prefix[i + 1] != NULL && tech_prefix[i + 1] != 0) {
                // now get all the symbols until end of string
                j = 0;
                while (tech_prefix[i + 1] != 0 && i < (sizeof(tech_prefix) - 4)) {
                    if (tech_prefix[i + 1] == '\\') {
                        tmp_add[j] = tech_prefix[i + 1];
                    } else {
                        tmp_add[j] = tech_prefix[i + 1];
                        j++;
                    }
                    i++;
                }
            } else {
                strcpy(tmp_add, "+");
            }
        }

        if (strlen(tmp_cut) && strlen(dst) >= strlen(tmp_cut)) {
            if (strncmp(tmp_cut, dst, strlen(tmp_cut)) == 0) {
                sprintf(tmp, "%s%s", tmp_add, dst + strlen(tmp_cut));
                if (strlen(tmp)) strcpy(dst_arg, tmp);
                return 1;
            }
        }

    } else {
        sprintf(tmp, "%s%s", tech_prefix, dst);
        strcpy(dst_arg, tmp);
        return 1;
    }

    return 0;

}


/*
    Format dial string for freeswitch
*/


static void m2_format_dial_string(calldata_t *cd) {

    int i = 0;

    for (i = 0; i < cd->routing_table_count; i++) {

        char dialstring[1024] = "";
        char callerid_from_number_pool[100] = "";
        char tp_destination[256] = "";
        char tp_callerid_name[60] = "";
        char tp_callerid_number[60] = "";

        strlcpy(tp_destination, cd->dst, sizeof(tp_destination));
        strlcpy(tp_callerid_name, cd->callerid_name, sizeof(tp_callerid_name));
        strlcpy(tp_callerid_number, cd->callerid_number, sizeof(tp_callerid_number));

        tpoints_t *tpoint_p = NULL;
        tpoint_p = cd->routing_table[i].tpoint;

        if (strlen(tpoint_p->callerid_number)) {
            strlcpy(tp_callerid_number, tpoint_p->callerid_number, sizeof(tp_callerid_number));
        }

        if (strlen(tpoint_p->callerid_name)) {
            strlcpy(tp_callerid_name, tpoint_p->callerid_name, sizeof(tp_callerid_name));
        }

        if (strlen(tpoint_p->tp_ipaddr)) {

            char *cidr_ptr = NULL;
            char *range_ptr = NULL;

            // check if ip address is in CIDR notation
            // in this case, we need to get single ip address from that subnet
            // based on selected algorithm (currently there is only random algorithm)
            cidr_ptr = strstr(tpoint_p->tp_ipaddr, "/");
            if (cidr_ptr) {
                char ipaddr[128] = "";
                m2_log(M2_NOTICE, "TP's IP [%s] is in CDR notation. Random IP from subnet will be generated\n", tpoint_p->tp_ipaddr);
                m2_get_random_ippaddr_from_subnet(cd, tpoint_p->tp_ipaddr, ipaddr);
                if (strlen(ipaddr)) {
                    m2_log(M2_NOTICE, "Random IP address from subnet was generated. Subnet: %s, random ip: %s\n", tpoint_p->tp_ipaddr, ipaddr);
                    strlcpy(tpoint_p->tp_ipaddr, ipaddr, sizeof(tpoint_p->tp_ipaddr));
                } else {
                    *cidr_ptr = '\0';
                    m2_log(M2_NOTICE, "Something is wrong with subnet calculation. Network address [%s] will be used instead", tpoint_p->tp_ipaddr);
                }
            }

            // check if ip address is in range notation
            // in this case, we need to get single ip address from that range
            // based on selected algorithm (currently there is only random algorithm)
            range_ptr = strstr(tpoint_p->tp_ipaddr, "-");
            if (range_ptr) {
                char ipaddr[128] = "";
                m2_log(M2_NOTICE, "TP's IP [%s] is in range notation. Random IP from this range will be generated\n", tpoint_p->tp_ipaddr);
                m2_get_random_ippaddr_from_range(cd, tpoint_p->tp_ipaddr, ipaddr);
                if (strlen(ipaddr)) {
                    m2_log(M2_NOTICE, "Random IP address from range was generated. Range: %s, random ip: %s\n", tpoint_p->tp_ipaddr, ipaddr);
                    strlcpy(tpoint_p->tp_ipaddr, ipaddr, sizeof(tpoint_p->tp_ipaddr));
                } else {
                    *range_ptr = '\0';
                    m2_log(M2_NOTICE, "Something is wrong with range calculation. Network address [%s] will be used instead", tpoint_p->tp_ipaddr);
                }
            }

        }

        if (cd->radius_auth_request) {

            int timeout = cd->timeout;
            int ringing_timeout = cd->op->ringing_timeout;

            if (tpoint_p->tp_ringing_timeout < ringing_timeout) {
                ringing_timeout = tpoint_p->tp_ringing_timeout;
            }

            // calculate timeout
            if (tpoint_p->tp_rate_after_exchange) {
                tpoint_p->tp_timeout = floorf(((tpoint_p->tp_user_balance_limit - tpoint_p->tp_user_balance) / tpoint_p->tp_rate_after_exchange) * 60);
            } else {
                tpoint_p->tp_timeout = global_call_timeout;
            }

            if (tpoint_p->tp_max_timeout > 0 && tpoint_p->tp_timeout > tpoint_p->tp_max_timeout) {
                tpoint_p->tp_timeout = tpoint_p->tp_max_timeout;
            }

            if (tpoint_p->tp_timeout < 0) {
                tpoint_p->tp_timeout = 0;
            }
            if (tpoint_p->tp_timeout > global_call_timeout) {
                tpoint_p->tp_timeout = global_call_timeout;
            }

            if (timeout > tpoint_p->tp_timeout) {
                timeout = tpoint_p->tp_timeout;
            }

            // add terminator tech prefix
            if (strlen(tpoint_p->tp_tech_prefix)) {
                // check if we have multiple tech prefix rules
                if (strchr(tpoint_p->tp_tech_prefix, '|')) {
                    // yes, we have multiple
                    char *pch;
                    char *saveptr;
                    char string[256] = "";

                    m2_log(M2_DEBUG, "Dst transformation contains multiple transformation rules\n");
                    strlcpy(string, tpoint_p->tp_tech_prefix, sizeof(string));
                    pch = strtok_r(string, "|", &saveptr);
                    while (pch != NULL) {
                        m2_log(M2_NOTICE, "Checking destination transformation rule: %s\n", pch);
                        if (tech_prefix_transform(tp_destination, pch)) {
                            m2_log(M2_NOTICE, "Dst transformation rule [%s] was applied, other rules will not be applied\n", pch);
                            break;
                        }
                        pch = strtok_r(NULL, "|", &saveptr);
                    }
                } else {
                    // single rule
                    tech_prefix_transform(tp_destination, tpoint_p->tp_tech_prefix);
                }

                m2_log(M2_NOTICE, "Dst before transformation [%s], after [%s], TP [%d%s]\n",
                    cd->dst, tp_destination, tpoint_p->tp_id, tpoint_p->tp_description);
            }

            // transform source number
            if (strlen(tpoint_p->tp_source_transformation)) {
                char original_tp_callerid_number[256] = "";
                strcpy(original_tp_callerid_number, tp_callerid_number);

                // check if we have multiple tech prefix rules
                if (strchr(tpoint_p->tp_source_transformation, '|')) {
                    // yes, we have multiple
                    char *pch;
                    char *saveptr;
                    char string[256] = "";

                    m2_log(M2_DEBUG, "Source transformation contains multiple transformation rules\n");
                    strlcpy(string, tpoint_p->tp_source_transformation, sizeof(string));
                    pch = strtok_r(string, "|", &saveptr);
                    while (pch != NULL) {
                        m2_log(M2_NOTICE, "Checking source transformation rule: %s\n", pch);
                        if (tech_prefix_transform(tp_callerid_number, pch)) {
                            m2_log(M2_NOTICE, "Src transformation rule [%s] was applied, other rules will not be applied\n", pch);
                            break;
                        }
                        pch = strtok_r(NULL, "|", &saveptr);
                    }
                } else {
                    // single rule
                    tech_prefix_transform(tp_callerid_number, tpoint_p->tp_source_transformation);
                }

                m2_log(M2_NOTICE, "Src before transformation [%s], after [%s], TP [%d%s]\n", original_tp_callerid_number, tp_callerid_number, tpoint_p->tp_id, tpoint_p->tp_description);
            }

            if (tpoint_p->tp_callerid_number_pool_id) {
                m2_get_callerid_from_number_pool(cd,
                                                 callerid_from_number_pool,
                                                 sizeof(callerid_from_number_pool),
                                                 tpoint_p->tp_callerid_number_pool_id,
                                                 tpoint_p->tp_callerid_number_pool_type,
                                                 tpoint_p->tp_callerid_number_pool_deviation);
                if (strlen(callerid_from_number_pool)) {
                    strlcpy(tp_callerid_number, callerid_from_number_pool, sizeof(tp_callerid_number));
                    strlcpy(tp_callerid_name, callerid_from_number_pool, sizeof(tp_callerid_name));
                }
            }

            if (cd->rn_number_used) {
                strcpy(tp_destination, cd->original_dst);
            }

            // Add routing string
            sprintf(dialstring, "%s/%s/%s/%s:%d/%d/%d", strlen(tp_callerid_number) > 0 ? tp_callerid_number : "-", strlen(tp_callerid_name) > 0 ? tp_callerid_name : "-",
                tp_destination, tpoint_p->tp_ipaddr, tpoint_p->tp_port, timeout, ringing_timeout);

            cd->dial_string_count++;
            // Routing kalon per Freeswitch - duhet me e ndryshu ne AVP ose me e ndryshu komplet Route out
            m2_radius_add_attribute_value_pair(cd, "Cisco-Command-Code", dialstring, M2_STANDARD_AVP);

            // Add terminator id
            char terminator_id_string[30] = "";
            sprintf(terminator_id_string, "%d", tpoint_p->tp_id);
            m2_radius_add_attribute_value_pair(cd, "terminator", terminator_id_string, M2_CISCO_AVP);

            // HGC mappings
            if (strlen(tpoint_p->tp_hgc_mapping)) {
                m2_radius_add_attribute_value_pair_tp(cd, "hgc_mapping", tpoint_p->tp_hgc_mapping, M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Interpret no answer as failed
            if (tpoint_p->tp_interpret_noanswer_as_failed) {
                m2_radius_add_attribute_value_pair_tp(cd, "interpret_noanswer_as_failed", "1", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Interpret busy as failed
            if (tpoint_p->tp_interpret_busy_as_failed) {
                m2_radius_add_attribute_value_pair_tp(cd, "interpret_busy_as_failed", "1", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Hide Q850 Header
            if (!cd->op->disable_q850 && tpoint_p->tp_disable_q850) {
                m2_radius_add_attribute_value_pair_tp(cd, "disable_q850", "1", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Forward RPID Header
            if (cd->op->forward_rpid && !tpoint_p->tp_forward_rpid) {
                m2_radius_add_attribute_value_pair_tp(cd, "forward_rpid", "0", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Forward PAI Header
            if (cd->op->forward_pai && !tpoint_p->tp_forward_pai) {
                m2_radius_add_attribute_value_pair_tp(cd, "forward_pai", "0", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Bypass Media
            if (!cd->op->bypass_media && tpoint_p->tp_bypass_media) {
                m2_radius_add_attribute_value_pair_tp(cd, "bypass_media", "1", M2_CISCO_AVP, tpoint_p->tp_id);
            }

            // Use PAI if CallerID is anonymous
            if (tpoint_p->use_pai_if_cid_anonymous) {
                m2_radius_add_attribute_value_pair_tp(cd, "use_pai_if_cid_anonymous", "1", M2_CISCO_AVP, tpoint_p->tp_id);
            }

        } else {
            m2_log(M2_WARNING, "Cannot add route, because cd->radius_auth_request is null\n");
        }

    }

}


/*
    Show routing table
*/


static void m2_show_routing_table(calldata_t *cd) {

    int i;

    m2_log(M2_NOTICE, "Generated Routing List for OP [%d%s], prefix[%s]:\n", cd->op->id, cd->op->description, cd->op->prefix);
    for (i = 0; i < cd->routing_table_count; i++) {
        m2_log(M2_NOTICE, "%sTP [%d%s] ip [%s], DP [%d%s], prefix: %s, rate: %f, weight: %d, quality_index: %.5f\n", cd->routing_table[i].failover ? "(*) " : "",
            cd->routing_table[i].tpoint->tp_id, cd->routing_table[i].tpoint->tp_description, cd->routing_table[i].tpoint->tp_ipaddr, cd->routing_table[i].dpeer->id,
            cd->routing_table[i].dpeer->name, cd->routing_table[i].tpoint->tp_prefix, cd->routing_table[i].tp_price, cd->routing_table[i].tp_weight, cd->routing_table[i].tp_quality_index);
    }

}


/*
    Function that returns index of DP in quality table
*/


static int m2_get_quality_tp_index(int dp_index, int tp_id) {

    int i = 0;
    int index = -1;

    for (i = 0; i < quality_dp_list[dp_index].tp_count; i++) {
        if (quality_dp_list[dp_index].tp_list[i].id == tp_id) {
            index = i;
            break;
        }
    }

    return index;

}


/*
    Function that returns index of DP in quality table
*/


static int m2_get_quality_dp_index(int dp_id) {

    int i = 0;
    int index = -1;

    for (i = 0; i < quality_dp_list_count; i++) {
        if (quality_dp_list[i].id == dp_id) {
            index = i;
            break;
        }
    }

    return index;

}


/*
    Function that sets call quality data
*/


static void m2_set_quality_data(int dp_index, int tp_index, int billsec, int answered, int timestamp) {

    // Create a new call quality instance
    quality_call_data_t *data = malloc(sizeof(quality_call_data_t));
    data->billsec = billsec;
    data->answered = answered;
    data->timestamp = timestamp;

    // add new node
    if (quality_dp_list[dp_index].tp_list[tp_index].data_tail == NULL) {
        quality_dp_list[dp_index].tp_list[tp_index].data_tail = data;
        quality_dp_list[dp_index].tp_list[tp_index].data_head = data;
        data->prev = NULL;
        data->next = NULL;
    } else {
        quality_call_data_t *node = quality_dp_list[dp_index].tp_list[tp_index].data_head;
        int found = 0;
        int counter = 0;

        while (node) {
            if (data->timestamp > node->timestamp) {
                found = 1;
                break;
            }
            node = node->next;
            counter++;
            if (counter > QUALITY_DATA_LIMIT) break;
        }

        if (found && node->prev != NULL) {
            data->prev = node->prev;
            data->next = node;
            node->prev->next = data;
            node->prev = data;
        } else {
            if (counter == 0) {
                quality_dp_list[dp_index].tp_list[tp_index].data_head->prev = data;
                data->next = quality_dp_list[dp_index].tp_list[tp_index].data_head;
                data->prev = NULL;
                quality_dp_list[dp_index].tp_list[tp_index].data_head = data;
            } else {
                quality_dp_list[dp_index].tp_list[tp_index].data_tail->next = data;
                data->prev = quality_dp_list[dp_index].tp_list[tp_index].data_tail;
                data->next = NULL;
                quality_dp_list[dp_index].tp_list[tp_index].data_tail = data;
            }
        }
    }

    // remove last node
    if (quality_dp_list[dp_index].tp_list[tp_index].total_calls >= QUALITY_DATA_LIMIT) {
        quality_call_data_t *tmp_tail = quality_dp_list[dp_index].tp_list[tp_index].data_tail;
        quality_dp_list[dp_index].tp_list[tp_index].data_tail = tmp_tail->prev;
        quality_dp_list[dp_index].tp_list[tp_index].data_tail->next = NULL;
        free(tmp_tail);
    } else {
        quality_dp_list[dp_index].tp_list[tp_index].total_calls++;
    }

}


/*
    Function that updates quality table after each call
*/


static void m2_update_quality_table(calldata_t *cd, int dp_id, int tp_id, int billsec, int answered, int timestamp, int lock) {

    if (disable_advanced_routing) return;

    int dp_index = -1;
    int tp_index = -1;

    // we are working with global variables, let's lock
    if (lock) m2_mutex_lock(QUALITY_TABLE_LOCK);

    // get DP index
    dp_index = m2_get_quality_dp_index(dp_id);

    if (dp_index == -1) {
        // create new DP record
        quality_dp_list = realloc(quality_dp_list, (quality_dp_list_count + 1) * sizeof(quality_dp_t));
        memset(&quality_dp_list[quality_dp_list_count], 0, sizeof(quality_dp_t));

        // create new TP record
        quality_dp_list[quality_dp_list_count].tp_list = realloc(quality_dp_list[quality_dp_list_count].tp_list, sizeof(quality_tp_t));
        memset(quality_dp_list[quality_dp_list_count].tp_list, 0, sizeof(quality_tp_t));

        // set indexes
        dp_index = quality_dp_list_count;
        tp_index = 0;

        // set id
        quality_dp_list[dp_index].id = dp_id;
        quality_dp_list[dp_index].tp_list[tp_index].id = tp_id;

        quality_dp_list[quality_dp_list_count].tp_count = 1;
        quality_dp_list_count++;
    }

    // check for errors, indexes SHOULDN'T be -1 here!
    if (dp_index == -1) {
        m2_log(M2_ERROR, "Something is wrong with quality table indexes (dp)!\n");
        if (lock) m2_mutex_unlock(QUALITY_TABLE_LOCK);
        return;
    }

    // get TP index
    if (tp_index == -1) {
        tp_index = m2_get_quality_tp_index(dp_index, tp_id);
    }

    // if TP not found, add new one
    if (tp_index == -1) {
        // create new TP record
        quality_dp_list[dp_index].tp_list = realloc(quality_dp_list[dp_index].tp_list, (quality_dp_list[dp_index].tp_count + 1) * sizeof(quality_tp_t));
        memset(&quality_dp_list[dp_index].tp_list[quality_dp_list[dp_index].tp_count], 0, sizeof(quality_tp_t));
        tp_index = quality_dp_list[dp_index].tp_count;
        quality_dp_list[dp_index].tp_list[tp_index].id = tp_id;
        quality_dp_list[dp_index].tp_count++;
    }

    // check for errors, indexes SHOULDN'T be -1 here!
    if (tp_index == -1) {
        m2_log(M2_ERROR, "Something is wrong with quality table indexes (tp)!\n");
        if (lock) m2_mutex_unlock(QUALITY_TABLE_LOCK);
        return;
    }

    if (timestamp > -1) {
        m2_set_quality_data(dp_index, tp_index, billsec, answered, timestamp);
    }

    // unlock thread
    if (lock) m2_mutex_unlock(QUALITY_TABLE_LOCK);

}


/*
    Get values for quality parameters by time/calls period
*/


static void m2_get_values_for_eval(quality_expression_data_t *expr_data, calldata_t *cd) {

    quality_call_data_t *data = expr_data->data;
    int counter = 0;
    int asr_total_calls = 0;
    int asr_answered_calls = 0;
    int acd_answered_calls = 0;
    int acd_total_billsec = 0;

    while (data) {
        if (counter < cd->op_quality_routing_data.total_calls) expr_data->total_calls++;
        if (counter < cd->op_quality_routing_data.total_billsec_calls) expr_data->total_billsec += data->billsec;
        if (counter < cd->op_quality_routing_data.asr_calls) {
            asr_total_calls++;
            if (data->answered) {
                asr_answered_calls++;
            }
        }
        if (counter < cd->op_quality_routing_data.acd_calls) {
            if (data->answered) {
                acd_answered_calls++;
                acd_total_billsec += data->billsec;
            }
        }
        if (counter < cd->op_quality_routing_data.answered_calls) {
            if (data->answered) {
                expr_data->total_answered_calls++;
            }
        }
        if (counter < cd->op_quality_routing_data.failed_calls) {
            if (!data->answered) {
                expr_data->total_failed_calls++;
            }
        }

        counter++;
        if (counter >= cd->op_quality_routing_data.max_iterator) break;
        data = data->next;
    }

    // calculate ACD
    if (acd_answered_calls) {
        expr_data->acd = (double)acd_total_billsec / acd_answered_calls;
    }

    // calculate ASR
    if (asr_answered_calls) {
        expr_data->asr = ((double)asr_answered_calls / asr_total_calls) * 100.0;
    }

}


/*
    Evaluate expression
*/


static double m2_calculate_quality_index(calldata_t *cd, int dp_id, int tp_id, double price, int weight, int percent, char *buffer) {

    if (disable_advanced_routing) return 0;

    int cookie;
    char *msg = NULL;
    quality_expression_data_t expr_data;
    int dp_index = -1;
    int tp_index = -1;

    cookie = le_loadexpr(cd->op_quality_routing_data.formula, &msg);
    if (msg) {
        m2_log(M2_ERROR, "Can't load: %s\n", msg);
        free(msg);
        le_unref(cookie);
        return 0;
    }

    // get DP and TP indexes
    dp_index = m2_get_quality_dp_index(dp_id);
    if (dp_index >= 0) tp_index = m2_get_quality_tp_index(dp_index, tp_id);

    if (dp_index == -1 || tp_index == -1) {
        m2_log(M2_WARNING, "Quality data not found for TP [%d] in DP [%d]!\n", tp_id, dp_id);
    }

    // get values
    memset(&expr_data, 0, sizeof(quality_expression_data_t));

    if (dp_index > -1 && tp_index > -1) {
        expr_data.data = quality_dp_list[dp_index].tp_list[tp_index].data_head;
        m2_get_values_for_eval(&expr_data, cd);
    }

    double asr = expr_data.asr;
    double acd = expr_data.acd;
    int total_billsec = expr_data.total_billsec;
    int total_calls = expr_data.total_calls;
    int total_answered_calls = expr_data.total_answered_calls;
    int total_failed_calls = expr_data.total_failed_calls;

    if (tp_index > -1 && total_calls == 0) {
        m2_log(M2_WARNING, "TP [%d] in DP [%d] does not have calls!\n", tp_id, dp_id);
    } else if (tp_index > -1 && total_answered_calls == 0) {
        m2_log(M2_WARNING, "TP [%d] in DP [%d] does not have answered calls!\n", tp_id, dp_id);
    }

    // set values
    le_setvar("ASR", asr);
    le_setvar("ACD", acd);
    le_setvar("TOTAL_CALLS", total_calls);
    le_setvar("TOTAL_ANSWERED", total_answered_calls);
    le_setvar("TOTAL_FAILED", total_failed_calls);
    le_setvar("TOTAL_BILLSEC", total_billsec);
    le_setvar("PRICE", price);
    le_setvar("WEIGHT", weight);
    le_setvar("PERCENT", percent);

    double quality_index = le_eval(cookie, &msg);

    if (buffer) {
        sprintf(buffer, "%d,%d,%d,%d,%d,%f,%f,%f,%f\n", tp_id, total_calls, total_answered_calls, total_failed_calls, total_billsec, asr, acd, quality_index, price);
    } else {
        m2_log(M2_NOTICE, "Quality data for TP [%d] in DP [%d[: total_calls: %d, total_answered_calls: %d, total_failed_calls: %d, total_billsec: %d, ASR: %.3f, ACD: %.3f, "
            "expression: %s, calculated quality index: %.5f\n",
            tp_id, dp_id, total_calls, total_answered_calls, total_failed_calls, total_billsec, asr, acd, cd->op_quality_routing_data.formula, quality_index);
    }

    if (msg) {
        m2_log(M2_ERROR, "Can't eval: %s\n", msg);
        free(msg);
        le_unref(cookie);
        return 0;
    }

    le_unref(cookie);

    return quality_index;

}


/*
    Get quality routing data from database by id
*/


static void m2_get_quality_data(calldata_t *cd) {

    if (disable_advanced_routing) return;

    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char query[2048] = "";
    int found = 0;

    memset(&cd->op_quality_routing_data, 0, sizeof(op_quality_routing_data_t));

    sprintf(query, "SELECT name, formula, asr_calls, acd_calls, total_calls, total_answered_calls, total_failed_calls, total_billsec_calls "
        "FROM quality_routings WHERE id = %d", cd->op->quality_routing_id);

    if (m2_mysql_query(cd, query, &connection)) {
        return;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        while ((row = mysql_fetch_row(result))) {
            if (row[0]) {
                strlcpy(cd->op_quality_routing_data.name, row[0], sizeof(cd->op_quality_routing_data.name));
                found = 1;
            }
            if (row[1]) strlcpy(cd->op_quality_routing_data.formula, row[1], sizeof(cd->op_quality_routing_data.formula));
            if (row[2]) cd->op_quality_routing_data.asr_calls = atoi(row[2]); else cd->op_quality_routing_data.asr_calls = 100;
            if (row[3]) cd->op_quality_routing_data.acd_calls = atoi(row[3]); else cd->op_quality_routing_data.acd_calls = 100;
            if (row[4]) cd->op_quality_routing_data.total_calls = atoi(row[4]); else cd->op_quality_routing_data.total_calls = 100;
            if (row[5]) cd->op_quality_routing_data.answered_calls = atoi(row[5]); else cd->op_quality_routing_data.answered_calls = 100;
            if (row[6]) cd->op_quality_routing_data.failed_calls = atoi(row[6]); else cd->op_quality_routing_data.failed_calls = 100;
            if (row[7]) cd->op_quality_routing_data.total_billsec_calls = atoi(row[7]); else cd->op_quality_routing_data.total_billsec_calls = 100;
        }
        mysql_free_result(result);
    }

    // select max value
    cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.asr_calls;
    if (cd->op_quality_routing_data.acd_calls > cd->op_quality_routing_data.max_iterator) cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.acd_calls;
    if (cd->op_quality_routing_data.total_calls > cd->op_quality_routing_data.max_iterator) cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.total_calls;
    if (cd->op_quality_routing_data.answered_calls > cd->op_quality_routing_data.max_iterator) cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.answered_calls;
    if (cd->op_quality_routing_data.failed_calls > cd->op_quality_routing_data.max_iterator) cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.failed_calls;
    if (cd->op_quality_routing_data.total_billsec_calls > cd->op_quality_routing_data.max_iterator) cd->op_quality_routing_data.max_iterator = cd->op_quality_routing_data.total_billsec_calls;

    if (found) {
        m2_log(M2_NOTICE, "Quality routing data: id: %d, name: %s, formula: %s, asr_calls: %d, acd_calls: %d, total_calls: %d, answered_calls: %d, failed_calls: %d, total_billsec_calls: %d\n",
            cd->op->quality_routing_id, cd->op_quality_routing_data.name, cd->op_quality_routing_data.formula, cd->op_quality_routing_data.asr_calls,
            cd->op_quality_routing_data.acd_calls, cd->op_quality_routing_data.total_calls, cd->op_quality_routing_data.answered_calls, cd->op_quality_routing_data.failed_calls,
            cd->op_quality_routing_data.total_billsec_calls);
    } else {
        m2_log(M2_WARNING, "Quality routing data not found [%d]\n", cd->op->quality_routing_id);
    }

}


/*
    Get TP price by number
*/


double m2_get_tp_price(calldata_t *cd, int tp_id, char *dst) {

    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char query[2048] = "";
    double price = 0;
    double exchange_rate = 1;
    char prefix_sql_line[9000] = "";
    char prefix[256] = "";

    m2_format_prefix_sql(prefix_sql_line, dst);

    // get tp price
    sprintf(query, "SELECT rates.prefix, ratedetails.rate, currencies.exchange_rate FROM devices "
        "JOIN tariffs ON tariffs.id = devices.tp_tariff_id "
        "JOIN rates ON (tariffs.id = rates.tariff_id AND rates.prefix IN (%s) AND (rates.effective_from < NOW() OR rates.effective_from IS NULL)) "
        "JOIN ratedetails ON (ratedetails.rate_id = rates.id AND (ratedetails.daytype = '%s' OR ratedetails.daytype = '') AND '%s' BETWEEN ratedetails.start_time AND ratedetails.end_time) "
        "LEFT JOIN currencies ON currencies.name = tariffs.currency "
        "WHERE devices.id = %d "
        "ORDER BY LENGTH(rates.prefix) DESC, rates.effective_from DESC "
        "LIMIT 1", prefix_sql_line, cd->daytype, cd->time, tp_id);

    if (m2_mysql_query(cd, query, &connection)) {
        return 0;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        while ((row = mysql_fetch_row(result))) {
            if (row[0]) strlcpy(prefix, row[0], sizeof(prefix));
            if (row[1]) {
                price = atof(row[1]);
            }
            if (row[2]) {
                exchange_rate = atof(row[2]);
                if (exchange_rate == 0) exchange_rate = 1;
            }
            m2_log(M2_NOTICE, "TP [%d] rate: %f, prefix: %s, exchange_rate: %f, rate after exchange_rate: %f\n", tp_id, price, prefix, exchange_rate, price / exchange_rate);
        }
        mysql_free_result(result);
    }

    return price / exchange_rate;

}


/*
    Get TP weight and percent in dial peer
*/


static int m2_get_tp_weight_percent(calldata_t *cd, int dp_id, int tp_id, int *weight, int *percent) {

    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char query[2048] = "";

    // get weight, percent
    sprintf(query, "SELECT tp_weight, tp_percent FROM dpeer_tpoints WHERE dial_peer_id = %d AND device_id = %d", dp_id, tp_id);

    if (m2_mysql_query(cd, query, &connection)) {
        return 0;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        while ((row = mysql_fetch_row(result))) {
            if (row[0]) {
                *weight = atoi(row[0]);
            }
            if (row[1]) {
                *percent = atoi(row[1]);
            }
        }
        mysql_free_result(result);
    }

    return 0;

}


/*
    Show quality routing data
*/


static void m2_show_quality_routing_data(calldata_t *cd, int dp_id, int qr_id, char *dst) {

    if (disable_advanced_routing) return;

    MYSQL_RES *result;
    MYSQL_ROW row;
    char csv_buffer[10000] = "";
    char query[10000] = "";
    int connection = 0;

    // delete old data
    sprintf(query, "DELETE FROM quality_routing_stats WHERE dp_id = %d AND quality_routing_id = %d", dp_id, qr_id);
    if (m2_mysql_query(cd, query, &connection)) {
        return;
    }
    mysql_connections[connection] = 0;

    cd->op->quality_routing_id = qr_id;
    m2_get_quality_data(cd);

    // get all tp in dial peer
    sprintf(query, "SELECT device_id FROM dpeer_tpoints WHERE dial_peer_id = %d", dp_id);
    if (m2_mysql_query(cd, query, &connection)) {
        return;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        while ((row = mysql_fetch_row(result))) {
            if (row[0]) {
                char buffer[1024] = "";
                int tp_id = atoi(row[0]);
                int tp_weight = 0;
                int tp_percent = 0;
                double tp_price = 0;

                m2_get_tp_weight_percent(cd, dp_id, tp_id, &tp_weight, &tp_percent);
                if (strlen(dst)) {
                    tp_price = m2_get_tp_price(cd, tp_id, dst);
                }

                m2_initialize_quality_data(cd, dp_id, tp_id);

                m2_mutex_lock(QUALITY_TABLE_LOCK);
                m2_calculate_quality_index(cd, dp_id, tp_id, tp_price, tp_weight, tp_percent, buffer);
                m2_mutex_unlock(QUALITY_TABLE_LOCK);

                m2_log(M2_NOTICE, "%s", buffer);
                strcat(csv_buffer, buffer);
            }
        }
        mysql_free_result(result);
    }

    if (strlen(csv_buffer)) {
        // insert new data
        sprintf(query, "INSERT INTO quality_routing_stats (quality_routing_id, dp_id, csv) VALUES(%d, %d, '%s')", qr_id, dp_id, csv_buffer);
        if (m2_mysql_query(cd, query, &connection)) {
            return;
        }
        mysql_connections[connection] = 0;
    }

}


/*
    If quality routing data is empty, get last N records from calls table
*/


static void m2_get_calls_from_database(calldata_t *cd, int dp_id, int tp_id) {

    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char query[2048] = "";

    // get calls
    sprintf(query, "SELECT * FROM (SELECT id, billsec, disposition, UNIX_TIMESTAMP(calldate), calldate FROM calls WHERE dst_device_id = %d AND (hangupcause < 300 OR hangupcause = 312) AND calldate >= NOW() - INTERVAL 1 DAY ORDER BY calldate DESC LIMIT %d) AS A ORDER BY A.calldate ASC", tp_id, QUALITY_DATA_LIMIT);

    if (m2_mysql_query(cd, query, &connection)) {
        return;
    }

    // query succeeded, get results and mark connection as available
    result = mysql_store_result(&mysql[connection]);
    mysql_connections[connection] = 0;

    if (result) {
        m2_mutex_lock(QUALITY_TABLE_LOCK);
        while ((row = mysql_fetch_row(result))) {
            if (row[0] && row[1] && row[2]) {
                m2_log(M2_DEBUG, "Call id: %s, billsec: %s, disposition: %s\n", row[0], row[1], row[2]);
                m2_update_quality_table(cd, dp_id, tp_id, atoi(row[1]), strcmp(row[2], "ANSWERED") == 0 ? 1 : 0, atoi(row[3]), 0);
            }
        }
        m2_mutex_unlock(QUALITY_TABLE_LOCK);
        mysql_free_result(result);
    }

}


/*
    Get initial call data from database
*/


static void m2_initialize_quality_data(calldata_t *cd, int dp_id, int tp_id) {

    if (disable_advanced_routing) return;

    int dp_index = -1;
    int tp_index = -1;
    int calls_checked = 0;

    check_quality_again:

    m2_mutex_lock(QUALITY_TABLE_LOCK);
    // get DP and TP indexes
    dp_index = m2_get_quality_dp_index(dp_id);
    if (dp_index >= 0) tp_index = m2_get_quality_tp_index(dp_index, tp_id);
    m2_mutex_unlock(QUALITY_TABLE_LOCK);

    if (dp_index == -1 || tp_index == -1) {
        if (calls_checked == 0) {
            calls_checked = 1;
            m2_log(M2_WARNING, "Quality data not found for TP [%d] in DP [%d]. Last %d records made within 24 hours from calls table will be selected to determine quality\n", tp_id, dp_id, QUALITY_DATA_LIMIT);
            m2_get_calls_from_database(cd, dp_id, tp_id);
            goto check_quality_again;
        } else {
            m2_log(M2_WARNING, "Quality data not found in calls table for TP [%d] in DP [%d]!\n", tp_id, dp_id);
            // insert fake call so that core would not search calls table again for this tp
            m2_update_quality_table(cd, dp_id, tp_id, 0, 0, -1, 1);
        }
    }

}


/*
    Set proper names for codecs
*/


static void m2_set_codec_nice_names(char *codec, char *name) {

    if (!strlen(name)) return;

    if (strcmp(name, "PCMA") == 0) {
        strcpy(codec, "G.711 A-law");
    } else if (strcmp(name, "PCMU") == 0) {
        strcpy(codec, "G.711 u-law");
    } else if (strcmp(name, "G722") == 0) {
        strcpy(codec, "G.722");
    } else if (strcmp(name, "G723") == 0) {
        strcpy(codec, "G.723.1");
    } else if (strcmp(name, "G726-16") == 0) {
        strcpy(codec, "G.726");
    } else if (strcmp(name, "G729") == 0) {
        strcpy(codec, "G.729");
    } else {
        strcpy(codec, name);
    }

}


/*
    Parse rn number from lnp header
*/


static void m2_get_rn_number(char *header, char *number) {

    char local_header[100] = "";
    char *start_ptr = NULL;
    char *end_ptr = NULL;

    strcpy(local_header, header);

    start_ptr = strstr(header, "rn=");

    if (start_ptr) {
        end_ptr = strchr(start_ptr, '@');

        if (end_ptr) {
            *end_ptr = '\0';
            strcpy(number, start_ptr + strlen("rn="));
        }
    }

}


/*
    Handle LNP (local number portability)
*/


static void m2_handle_lnp(calldata_t *cd) {

    if (!strlen(cd->lnp)) return;

    m2_get_rn_number(cd->lnp, cd->rn);

    if (strlen(rn_prefix_if_missing) && strncmp(cd->rn, rn_prefix_if_missing, strlen(rn_prefix_if_missing)) != 0) {
        char new_rn_number[100] = "";

        m2_log(M2_DEBUG, "Adding %s to rn number %s\n", rn_prefix_if_missing, cd->rn);
        sprintf(new_rn_number, "%s%s", rn_prefix_if_missing, cd->rn);
        strcpy(cd->rn, new_rn_number);
    }
}
