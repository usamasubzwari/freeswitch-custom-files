
static void m2_active_calls_array_init() {

    // locking in m2_instantiation

    int i;
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        active_calls_array[i].cd = NULL;
        active_calls_array[i].status = 0;
        pthread_mutex_init(&active_calls_array[i].lock, NULL);

    }

    calldata_t *cd = NULL;
    m2_log(M2_NOTICE, "Active Calls Array initiated\n");


}


static void m2_active_calls_array_destroy() {

    calldata_t *cd = NULL;

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock start - m2_active_calls_array_destroy");
#endif
    m2_mutex_lock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock end - m2_active_calls_array_destroy");
#endif

    int i;
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        active_calls_array[i].cd = NULL;
        active_calls_array[i].status = 0;
        pthread_mutex_destroy(&active_calls_array[i].lock);

    }

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock start - m2_active_calls_array_destroy");
#endif
    m2_mutex_unlock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock end - m2_active_calls_array_destroy");
#endif

    m2_log(M2_NOTICE, "Active Calls Array destroyed\n");

}



static void m2_set_active_call(calldata_t *cd) {


    // add cd to cd hash by uniqueid
    cd_hash_t *cdh = NULL;
    cdh = (cd_hash_t*)malloc(sizeof(cd_hash_t));
    strncpy(cdh->uniqueid, cd->uniqueid, sizeof(cdh->uniqueid));
    cdh->cd = cd;
    pthread_rwlock_wrlock(&cd_hash_lock);   // write lock to allow only one thread to write to the hash at the same time
    HASH_ADD_STR(cd_hash, cd->uniqueid, cdh);
    pthread_rwlock_unlock(&cd_hash_lock);

    // connect cd with active_calls_array
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock start - m2_set_active_call");
#endif
    m2_mutex_lock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock end - m2_set_active_call");
#endif

    // get active call id
    cd->active_call_id = m2_get_activecall_id();

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock start - m2_set_active_call");
#endif
    m2_mutex_unlock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock end - m2_set_active_call");
#endif

    // set call_id as 'taken' so other new calls can not get this id
    if (cd->active_call_id) {
        active_calls_array[cd->active_call_id].status = 1;
        active_calls_array[cd->active_call_id].cd = cd;
    } else {
        m2_log(M2_ERROR, "Not possible to get active_call_id. Report to developers.\n");
    }

    cd->call_state = M2_PROCESSING_STATE;
    cd->active_call_is_set = 1;


    m2_log(M2_DEBUG, "Changed call state to [%s], active_call_id [%i]\n", call_state_str[M2_PROCESSING_STATE] == NULL ? "UNKNOWN" : call_state_str[M2_PROCESSING_STATE], cd->active_call_id);


    m2_mutex_lock(COUNTERS_LOCK);
    connp_index[cd->op->id].in_active_calls++;
    cd->user->in_active_calls++;
    m2_mutex_unlock(COUNTERS_LOCK);


}



static void m2_unset_active_call(calldata_t *cd) {

    if (active_calls_count == 0 && shutdown_when_zero_calls == 1) {

        int timeout = 5;

        if (active_calls_check_timer_period > 0) {
            timeout = active_calls_check_timer_period + 5;
        }

        m2_log(M2_WARNING, "Variable 'shutdown_when_zero_calls' is set to 1 and active calls count is 0. Shutting down radius in %d seconds...\n", timeout);
        if (clean_shutdown) {
            system("/usr/src/m2/core/m2_core_recompile.sh CLEAN");
        }

        m2_flush_calls_to_database(1);
        m2_remove_calls_from_db();
        m2_init_terminate_radius();
    }

    if (!cd->active_call_is_set) {
        return;
    }

    m2_mutex_lock(COUNTERS_LOCK);
    connp_index[cd->op->id].in_active_calls--;
    cd->user->in_active_calls--;
    m2_mutex_unlock(COUNTERS_LOCK);

    // remove cd from cd hash by uniqueid
    cd_hash_t *cdh = NULL;
    if (cd_hash != NULL){
        pthread_rwlock_wrlock(&cd_hash_lock);     // write lock to allow only one thread to write to the hash at the same time
        HASH_FIND_STR(cd_hash, cd->uniqueid, cdh);
        if (cdh != NULL){
            HASH_DEL(cd_hash, cdh);
            free(cdh);
            //m2_log(M2_DEBUG, "CD HASH: cd by uniqueid [%s] deleted\n", cd->uniqueid);
        }
        pthread_rwlock_unlock(&cd_hash_lock);
    }


    active_calls_array[cd->active_call_id].status = -1;   // finished but not yet marked as free space (ac db table not updated for this call yet)

}


/*

    This functions works on its own separate thread and in real time checks active calls

    Function does several things:

        * checks timeout for radius requests
        * counts user's balance in real time
        * hangups calls if necessary
        * prints active calls to console (if enabled by 'm2 logger activecalls on')

*/


static void *m2_handle_active_calls() {

    int auth_resp_counter = 0;

    active_calls_check_timer_running = 1;

    while (1) {
        sleep(1);

        m2_hac_uptime++;  // how many (approx) seconds passed from the first call

        active_calls_check_counter++;
        balance_check_counter++;
        acct_timeout_check_counter++;
        user_fetch_counter++;
        balance_update_counter++;
        connp_update_counter++;

        // Authorization resp logic (ask MK) every AUTH_RESP_T seconds
        if (AUTH_RESP_T){
            auth_resp_counter++;
            if (auth_resp_counter > AUTH_RESP_T){
                auth_resp();
                auth_resp_counter = 0;
            }
        }

        // Check if internal active calls need to be updated to database
        if (acct_timeout_timer_period && (acct_timeout_check_counter >= acct_timeout_timer_period)) {

            m2_check_accounting_timeouts();

            acct_timeout_check_counter = 0;
        }

        // Check if internal active calls need to be updated to database
        if (active_calls_check_timer_period && (active_calls_check_counter >= active_calls_check_timer_period)) {

            m2_check_active_calls();

            active_calls_check_counter = 0;
        }

        // Update balance differences to database
        if (balance_update_period && (balance_update_counter >= balance_update_period)) {
            m2_update_user_balances_to_database();
            balance_update_counter = 0;
        }

        // Fetch and insert/update users in internal users list
        if (user_fetch_period && (user_fetch_counter >= user_fetch_period)) {
            m2_fetch_users();
            user_fetch_counter = 0;
        }

        // Fetch and update connp data in the internal index/array
        if (connp_list_ttl && (connp_update_counter >= connp_list_ttl)) {

            m2_update_connp_index(0);

            // together with connp index, same logic, no need to duplicate code
            m2_tp_dp_cache_update();

            connp_update_counter = 0;
        }

        // Realtime balance check (recalculates call price for each user's concurrent calls)
        if (balance_check_timer_period && (balance_check_counter >= balance_check_timer_period)) {

            m2_realtime_balance_check();

            balance_check_counter = 0;
        }

        // Hangup calls that should be terminated internally
        // For example acct start/stop timeout or low balance
        if (hangup_requested) {
            m2_system_hangup_calls();
        }

        if (stop_active_calls_check_timer) {
            break;
        }
    }

    active_calls_check_timer_running = 0;
    pthread_exit(NULL);
}


/*
    Check for accounting start/stop timeouts

    Used by m2_handle_active_calls
    Max 1 time/s, default once in every 5s
*/


static void m2_check_accounting_timeouts() {

    if (!active_calls_count) return; // nothing to check if no calls

    // this variable is used by m2_log function
    calldata_t *cd = NULL;

    double current_time;
    calldata_t *node = NULL;

    // get current time
    struct timeb tp;
    ftime(&tp);
    current_time = tp.time + (tp.millitm / 1000.0);

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock start - m2_check_accounting_timeouts");
#endif
    m2_mutex_lock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock end - m2_check_accounting_timeouts");
#endif

    int i;
    int calls_processed = 0;

    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        if (active_calls_array[i].status > 0 && active_calls_array[i].cd != NULL) {
            node = active_calls_array[i].cd;

            // do not check new nodes (check only ringing/answered calls)
            if (node->call_state > M2_NEW_STATE) {

                // protection from not receiving acct start packet
                if (node->call_state < M2_ANSWERED_STATE && ((int)(current_time - node->start_time) > start_timeout)) {
                    m2_log(M2_ERROR, "Current user's call reached START packet timeout (timeout: %d, current wait time: %d). "
                        "User_id: %d, uniqueid: %s, channel: %s, Call should be terminated (HANG)\n",
                        start_timeout, (int)(current_time - node->start_time), node->op->user_id,
                        node->uniqueid, node->chan_name);
                    hangup_requested = 1;
                    node->system_hangup_reason = M2_HANGUP_ACCT_START_TIMEOUT;
                    m2_set_hangupcause(node, 314);
                }

                // protection from not receiving acct stop packet
                if (node->call_state == M2_ANSWERED_STATE && (int)(current_time - node->answer_time) > stop_timeout) {
                    m2_log(M2_ERROR, "Current user's call reached STOP packet timeout (timeout: %d, current wait time: %d). "
                        "User_id: %d, uniqueid: %s, channel: %s, Call should be terminated (HANG)\n",
                        stop_timeout, (int)(current_time - node->start_time), node->op->user_id,
                        node->uniqueid, node->chan_name);
                    hangup_requested = 1;
                    node->system_hangup_reason = M2_HANGUP_ACCT_STOP_TIMEOUT;
                    m2_set_hangupcause(node, 315);
                }
            }

            if (calls_processed++ > active_calls_count) break;  // control to not check whole array

        }
    } // for

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock start - m2_check_accounting_timeouts");
#endif
    m2_mutex_unlock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock end - m2_check_accounting_timeouts");
#endif

}


/*
    Check if active calls need to be updated to database

    Used by m2_handle_active_calls
    Max 1 time/s, default once in every 5s
*/


static void m2_check_active_calls() {

    calldata_t *cd = NULL;

    int update_query_initialized = 0;
    int delete_query_initialized = 0;
    int active_calls_to_update = 0;   // shows if there is atleast one new call and/or answered call
    int active_calls_to_delete = 0;   // shows if there is atleast one finished call
    char query_buffer[512] = "";
    calldata_t *node = NULL;

/*
    m2_log(M2_DEBUG, "ACAL lock start - m2_check_active_calls");
    m2_mutex_lock(AC_ARRAY_LOCK);
    m2_log(M2_DEBUG, "ACAL lock end - m2_check_active_calls");
*/

    int i;
    int calls_processed = 0;

    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        if (active_calls_array[i].status > 0 && active_calls_array[i].cd != NULL) {
            node = active_calls_array[i].cd;

            // Check active calls (in ringing or answered states)
            if (node->call_state > M2_ROUTING_STATE && node->active_call_update == 1 && node->active_call_id) {

                active_calls_to_update++;

                int active_call_id = node->active_call_id;
                char channel[256] = "";
                char dstchannel[256] = "";
                int tp_id = 0;
                int tp_user_id = 0;
                double tp_rate = 0;
                tpoints_t *tpoint = NULL;

                // against double acc packet
                if (node->dial_count < node->routing_table_count){
                    tpoint = node->routing_table[node->dial_count].tpoint;

                    if (tpoint) {
                        tp_id = tpoint->tp_id;
                        tp_user_id = tpoint->tp_user_id;
                        tp_rate = tpoint->tp_rate_after_exchange;
                    }
                }

                sprintf(channel, "%s", node->chan_name);
                sprintf(dstchannel, "%s", node->chan_name);

                char prefix[100] = "";
                strlcpy(prefix, node->op->prefix, sizeof(prefix));
                if (tpoint && strlen(tpoint->tp_prefix) > strlen(prefix)) {
                    strlcpy(prefix, tpoint->tp_prefix, sizeof(prefix));
                }

                sprintf(query_buffer, "(%d,%d,'%s','%s',%s,'%s','%s',%d,%d,'%s','%s','%s',%d,%d,'%s',%f,%f,1),",
                    active_call_id, node->server_id, node->uniqueid, node->calldate, node->answer_time_str,
                    node->original_src, node->dst, node->op->id, tp_id, channel, dstchannel,
                    prefix, tp_user_id, node->op->user_id, node->dst, node->op_rate_after_exchange, tp_rate);

                // initialize active calls update query
                if (!update_query_initialized) {
                    memset(active_calls_query, 0, sizeof(active_calls_query));
                    sprintf(active_calls_query, "%s", active_calls_insert_fields);
                    update_query_initialized = 1;
                }

                strlcat(active_calls_query, query_buffer, sizeof(active_calls_query));

                node->active_call_updated = 1;
                node->active_call_update = 0;

                if (active_calls_to_update == ACTIVE_CALLS_BATCH_SIZE) {
                    m2_update_active_calls_to_database(1);
                    // initialize active calls update query
                    memset(active_calls_query, 0, sizeof(active_calls_query));
                    sprintf(active_calls_query, "%s", active_calls_insert_fields);
                    active_calls_to_update = 0;
                }
            }

            if (calls_processed++ > active_calls_count) break;  // control to not check whole array

        }

    } // for



    // Check finished calls
    // Finished calls are saved in active_call_status array with value -1
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {
        if (active_calls_array[i].status == -1) {
            int active_call_id = i;

            // enable sql update
            active_calls_to_delete++;


            // completely destroy call detail record from the memory (GARBAGE COLLECTION)
            if (active_calls_array[i].cd != NULL) {
                m2_log(M2_DEBUG, "GARBAGE: freeing cd: %s", active_calls_array[i].cd->uniqueid);
                m2_cd_free_memory(&(active_calls_array[i].cd));
                active_calls_array[i].cd = NULL;
            }

            // reset this active_call_id so other calls can take it (when cd is already free)
            active_calls_array[i].status = 0;

            // if this instance of radius is temporary (new instance of radius with newer core was executed by recompile script)
            // then set active call id to be 'backwards', for example if active call id is 1, then make it 1999 (if call limit is 2000)
            /* disabled for now, because id selection works differently now and this is not a safe way to give free id
            if (m2_recompile_executed) {
                active_call_id = CALL_LIMIT - active_call_id;
            }
            */

            // initialize active calls delete query
            if (!delete_query_initialized) {
                memset(active_calls_delete_query, 0, sizeof(active_calls_delete_query));
                sprintf(active_calls_delete_query, "%s", active_calls_delete_fields);
                delete_query_initialized = 1;
            }

            // format sql string which will hide active call
            sprintf(query_buffer, "(%d,0),", active_call_id);
            strlcat(active_calls_delete_query, query_buffer, sizeof(active_calls_delete_query));

            if (active_calls_to_delete == ACTIVE_CALLS_BATCH_SIZE) {
                m2_update_active_calls_to_database(0);
                // initialize active calls update query
                memset(active_calls_delete_query, 0, sizeof(active_calls_delete_query));
                sprintf(active_calls_delete_query, "%s", active_calls_delete_fields);
                active_calls_to_delete = 0;
            }
        }
    }

/*
    m2_log(M2_DEBUG, "ACAL unlock start - m2_check_active_calls");
    m2_mutex_unlock(AC_ARRAY_LOCK);
    m2_log(M2_DEBUG, "ACAL unlock end - m2_check_active_calls");
*/

    // update active calls
    if (active_calls_to_update) {
        m2_update_active_calls_to_database(1);
    }

    // update finished calls
    if (active_calls_to_delete) {
        m2_update_active_calls_to_database(0);
    }

    //calldata_t *cd = NULL;
    //m2_log(M2_DEBUG, "m2_check_acctive_calls completed");

}


/*
    Realtime balance check

    Used by m2_handle_active_calls
    Max 1 time/s, default once in 5s
    /etc/m2/system.conf balance_check_period

*/


static void m2_realtime_balance_check() {

    calldata_t *node = NULL;

    double current_time;
    struct timeb tp;
    ftime(&tp);
    current_time = tp.time + (tp.millitm / 1000.0);

    m2_reset_realtime_balance_check_data();

#if DEBUG_LOCKS
    calldata_t *cd = NULL;
    m2_log(M2_DEBUG, "ACAL lock start - m2_realtime_balance_check");
#endif
    m2_mutex_lock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock end - m2_realtime_balance_check");
#endif

    // Calculate total price of all user's calls
    int i;
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        if (active_calls_array[i].status > 0 && active_calls_array[i].cd != NULL) {
            node = active_calls_array[i].cd;

            if (node->call_state == M2_ANSWERED_STATE) {
                int calculated_billsec = 0;
                double calculated_call_price = 0;
                double rate = node->op_rate;
                double connection_fee = node->op_connection_fee;
                double exchange_rate = node->op_exchange_rate;
                int min_time = node->op_min_time;
                int increment = node->op_increment;
                int grace_time = node->op->grace_time;

                // skip if call does not have a user
                if (!node->user) goto check_next_node;

                // check only answered calls that have billsec
                if (node->answer_time == 0) goto check_next_node;

                int billsec = (int)ceil(current_time - node->answer_time);

                if (billsec < 1) goto check_next_node;

                // check op grace time
                if (grace_time > 0 && grace_time >= billsec) {
                    billsec = 0;
                }

                // calculate current call price
                if (billsec) {
                    m2_calculate_call_price((billsec + balance_check_timer_period + 1), rate, min_time, increment, connection_fee, &calculated_billsec, &calculated_call_price);
                }

                // convert to default currency
                calculated_call_price = calculated_call_price / exchange_rate;
                node->user->tmp_total_price += calculated_call_price;

                if ((node->user->balance - node->user->tmp_total_price) >= node->user->balance_min) {
                    node->user->total_billsec += calculated_billsec;
                }

                node->user->total_real_billsec += billsec + balance_check_timer_period + 1;
                node->user->answered_calls++;
            }

            check_next_node:
            ;  // this is necessary to avoid compile error: label at end of compound statement
        }
    } // for

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock start - m2_realtime_balance_check");
#endif
    m2_mutex_unlock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock end - m2_realtime_balance_check");
#endif

    // Prices are now calculated, let's check if limits are not reached
    m2_check_user_balance_limits();

    //m2_log(M2_DEBUG, "m2_realtime_balance_check");

}


/*
    Terminate calls by system request (for example acct start/stop timeouts, real time balance check)
*/


static void m2_system_hangup_calls() {

    if (!hangup_requested) {
        return;
    }

    calldata_t *node = NULL;

#if DEBUG_LOCKS
    calldata_t *cd = NULL;
    m2_log(M2_DEBUG, "ACAL lock start - m2_system_hangup_calls");
#endif
    m2_mutex_lock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL lock end - m2_system_hangup_calls");
#endif

    m2_mutex_lock(AC_HANG_LOCK);

    int i;
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {

        if (active_calls_array[i].status > 0 && active_calls_array[i].cd != NULL) {
            node = active_calls_array[i].cd;

            // Hangup all calls that were requested to be hangup by the system
            if (node->system_hangup_reason && node->call_state < M2_FINISHED_STATE) {

                //fill the buffer array which calls needs to hang
                hangup_calls_array[hangup_calls_count].server_id = node->server_id;
                strncpy(hangup_calls_array[hangup_calls_count].uniqueid, node->uniqueid, sizeof(hangup_calls_array[hangup_calls_count].uniqueid));
                hangup_calls_count++;

                m2_do_accounting_routine(&node, NULL);

            }

        }

    } // for

    m2_mutex_unlock(AC_HANG_LOCK);

#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock start - m2_system_hangup_calls");
#endif
    m2_mutex_unlock(AC_ARRAY_LOCK);
#if DEBUG_LOCKS
    m2_log(M2_DEBUG, "ACAL unlock end - m2_system_hangup_calls");
#endif

    hangup_requested = 0;

}


/*
    Send hangup command to the Freeswitch over the system
    In a separate thread to do not lag main loop
*/

static void m2_system_hangup_calls_execute() {

    meter.ac_hang_count_start++;
    double start_time = m2_get_current_time();

    calldata_t *cd = NULL;
    int i;
    char server_ip[256] = "";
    char systemcmd[1024] = "";

    // make a copy of the buffer array to release the lock asap (and reset the global array)
    m2_mutex_lock(AC_HANG_LOCK);

    int hc_count = hangup_calls_count;

    for (i=0; i < hangup_calls_count; i++) {
        hc_array[i].server_id = hangup_calls_array[i].server_id;
        strcpy(hc_array[i].uniqueid, hangup_calls_array[i].uniqueid);

        hangup_calls_array[i].server_id = 0;
        strcpy(hangup_calls_array[i].uniqueid, "");
    }
    hangup_calls_count = 0;

    m2_mutex_unlock(AC_HANG_LOCK);


    m2_log(M2_DEBUG, "HANG: Ready to hang [%i] call(s)", hc_count);


    for (i=0; i < hc_count; i++) {

        if (hc_array[i].server_id == server_id) {
            strcpy(server_ip, "127.0.0.1");
        } else {
            m2_get_freeswitch_server_ip(hc_array[i].server_id, server_ip, sizeof(server_ip) - 1);
        }

        if (strlen(server_ip) && strlen(hc_array[i].uniqueid)) {
            sprintf(systemcmd, "fs_cli -H '%s' -t 500 -T 500 -x 'uuid_kill %s' &", server_ip, hc_array[i].uniqueid);

            m2_log(M2_WARNING, "HANG: Hanging up call with uniqueid [%s] on server [%s], command [%s]\n", hc_array[i].uniqueid, server_ip, systemcmd);

            system(systemcmd);

        } else {
            m2_log(M2_ERROR, "HANG: Cannot hangup call. UniqueID [%s] Server ID [%d]\n", hc_array[i].uniqueid, hc_array[i].server_id);
        }

    }


    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.ac_hang_time += run_time;
    meter.ac_hang_count++;
    if (run_time > meter.ac_hang_time_max) meter.ac_hang_time_max = run_time;
    if (run_time > meter.ac_hang_time_maxps) meter.ac_hang_time_maxps = run_time;

    meter.hanged_calls_total++;

    m2_log(M2_DEBUG, "HANG: Hanged [%i] call(s) in [%f]s", hc_count, run_time);

}



/*
    Timer function in separate thread which runs in intervals and calls the call hangup function
*/

static void *m2_system_hangup_calls_execute_thread() {

    calldata_t *cd = NULL;
    m2_log(M2_DEBUG, "HANGUP CALLS: Timer activated\n");

    while(1) {

        sleep(1);

        if (hangup_calls_count) {
            m2_system_hangup_calls_execute();
        }

        if (stop_batch_timer) break;

    }

    pthread_exit(NULL);

}



/*
    Insert new calls to activecalls table
*/


static int m2_update_active_calls_to_database(int insert) {

    int connection = 0;
    int query_len = 0;

    if (active_calls_enabled == 0) return 0;

    // update new/answered calls
    if (insert && strlen(active_calls_query)) {
        query_len = strlen(active_calls_query) - 1;
        // remove last comma
        active_calls_query[query_len] = 0;
        // add query ending
        strlcat(active_calls_query, active_calls_insert_fields_ending, sizeof(active_calls_query));

        if (async_active_calls_update) {
            m2_async_active_calls_update(active_calls_query);
        } else {
            // send query
            m2_mysql_query(NULL, active_calls_query, &connection);
            mysql_connections[connection] = 0;
        }
    }

    // update finished calls
    if (!insert && strlen(active_calls_delete_query)) {
        query_len = strlen(active_calls_delete_query) - 1;
        // remove last comma
        active_calls_delete_query[query_len] = 0;
        // add query ending
        strlcat(active_calls_delete_query, active_calls_delete_fields_ending, sizeof(active_calls_delete_query));

        if (async_active_calls_update) {
            m2_async_active_calls_update(active_calls_delete_query);
        } else {
            // send query
            m2_mysql_query(NULL, active_calls_delete_query, &connection);
            mysql_connections[connection] = 0;
        }
    }

    return 0;

}


/*
    Initialize active calls in the database
*/


static int m2_init_active_calls() {

    int i = 0;
    int connection = 0;
    char query[10000] = "";
    char buffer[2048] = "";

    sprintf(buffer, "TRUNCATE activecalls"); // faster than DELETE FROM table

    if (!m2_mysql_query(NULL, buffer, &connection)) {
        mysql_connections[connection] = 0;
    }

    // insert fake active calls into activecalls table
    // insert in bacthes because it is faster

    memset(query, 0, sizeof(query));
    sprintf(query, "INSERT INTO activecalls(id,active) VALUES ");

    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {
        sprintf(buffer, "(%d,0),", i);
        strlcat(query, buffer, sizeof(query));
        if (i % 100 == 0 && i > 0) {
            // remove last comma
            query[strlen(query) - 1] = 0;
            m2_mysql_query(NULL, query, &connection);
            mysql_connections[connection] = 0;
            memset(query, 0, sizeof(query));
            sprintf(query, "INSERT INTO activecalls(id,active) VALUES ");
        }
    }

    if (strlen(query) > strlen("INSERT INTO activecalls(id,active) VALUES ")) {
        // remove last comma
        query[strlen(query) - 1] = 0;
        m2_mysql_query(NULL, query, &connection);
        mysql_connections[connection] = 0;
    }

    return 0;

}


/*
    Get free activecalls.id
*/

static int m2_get_activecall_id() {

/*
    int i;
    for (i = 1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {
        if (active_calls_array[i].status == 0) {
            return i;
        }
    }

    return 0;
*/
// -----------

    // fast way to get next free ac_id
    // remembers last given ac_last_id and starts searching from it
    // our array is [1...ac_last_id...ACTIVE_CALLS_ARRAY_COUNT] so we do 2 passes over the interval: [1..ac_last_id] and [ac_last_id..ACTIVE_CALLS_ARRAY_COUNT]

    if (ac_last_id+1 >= ACTIVE_CALLS_ARRAY_COUNT) ac_last_id = 0;  //to handle last element in the array and reset the marker

    int i;
    // period from ac_last_id till the array's end
    for (i = ac_last_id+1; i < ACTIVE_CALLS_ARRAY_COUNT; i++) {
        if (active_calls_array[i].status == 0) {
            ac_last_id = i;
            return i;
        }
    }

    // period from the start till the ac_last_id
    for (i = 1; i < ac_last_id; i++) {
        if (active_calls_array[i].status == 0) {
            ac_last_id = i;
            return i;
        }
    }

    return 0;

}


/*
    Mark all calls as finished in activecalls table
*/


static int m2_remove_calls_from_db() {

    if (m2_recompile_executed) return 0;

    char sqlcmd[1024] = "";
    int connection = 0;

    sprintf(sqlcmd, "UPDATE activecalls SET active = 0");
    m2_mysql_query(NULL, sqlcmd, &connection);
    mysql_connections[connection] = 0;

    return 0;

}


/*
    Create thread which will be used to update active calls
*/


static void m2_async_active_calls_update(char *query) {

    calldata_t *cd = NULL;
    pthread_t async_ac_update_thread;
    pthread_attr_t async_ac_update_attr;

    m2_log(M2_DEBUG, "Creating active calls update thread\n");

    async_ac_update_args_t *args = (async_ac_update_args_t *)malloc(sizeof(async_ac_update_args_t));
    args->finished_copying = 0;
    args->query = query;

    pthread_attr_init(&async_ac_update_attr);
    pthread_attr_setdetachstate(&async_ac_update_attr, PTHREAD_CREATE_DETACHED);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if (pthread_create(&async_ac_update_thread, &async_ac_update_attr, m2_async_active_calls_update_thread, args)) {
        free(args);
    }

    pthread_attr_destroy(&async_ac_update_attr);

    // Wait until thread finished copying query to its local buffer
    while (!args->finished_copying);

    free(args);

}


/*
    Handle async active calls update
*/


static void *m2_async_active_calls_update_thread(void *args_param) {

    int connection = 0;
    char local_query[ACTIVE_CALLS_BUFFER_SIZE] = "";
    async_ac_update_args_t *args = args_param;

    strcpy(local_query, args->query);

    // Set flag once we have copied global query to our local query
    args->finished_copying = 1;

    if (!m2_mysql_query(NULL, local_query, &connection)) {
        mysql_connections[connection] = 0;
    }

    pthread_exit(NULL);

}
