
static int m2_accounting(calldata_t *cd) {

    m2_log(M2_NOTICE, "----------------------------------- ACCOUNTING ------------------------------------\n");

    int connection = 0;
    char query[2048] = "";

    tpoints_t *tpoint = NULL;
    if (cd->routing_table) {
        tpoint = cd->routing_table[cd->dial_count - 1].tpoint;
    }

    int call_answered = 0;

    if (!strcmp(cd->dialstatus, "ANSWERED") && cd->billsec) {
        call_answered = 1;
    }

    if (call_answered) {

        int op_billsec = cd->billsec;
        int tp_billsec = cd->billsec;

        // check op grace time
        if (cd->op->grace_time > 0 && cd->op->grace_time >= op_billsec) {
            op_billsec = 0;
            m2_log(M2_NOTICE, "OP billsec after grace time [%d] is %d\n", cd->op->grace_time, op_billsec);
        }

        // check tp grace time
        if (tpoint->tp_grace_time > 0 && tpoint->tp_grace_time >= tp_billsec) {
            tp_billsec = 0;
            m2_log(M2_NOTICE, "TP billsec after grace time [%d] is %d\n", tpoint->tp_grace_time, tp_billsec);
        }

        // counting price for originator
        if (op_billsec) {
            m2_calculate_call_price(op_billsec, cd->op_rate, cd->op_min_time, cd->op_increment, cd->op_connection_fee, &cd->op_billsec, &cd->op_price);
        }

        // save original call price and use it to deduct from user's balance
        cd->op_original_price = cd->op_price;

        // counting price for terminator
        if (tp_billsec) {
            m2_calculate_call_price(tp_billsec, tpoint->tp_rate, tpoint->tp_min_time, tpoint->tp_increment, tpoint->tp_connection_fee, &tpoint->tp_billsec, &tpoint->tp_price);
        }

        m2_log(M2_NOTICE, "OP billsec: %i, price: %f, rate: %f\n", cd->op_billsec, cd->op_price, cd->op_rate);
        m2_log(M2_NOTICE, "TP billsec: %i, price: %f, rate: %f\n", tpoint->tp_billsec, tpoint->tp_price, tpoint->tp_rate);

        // ---------- apply exchange rate to support currencies -----------------------------

        if (!cd->op_exchange_rate) {
            cd->op_exchange_rate = 1;
        }

        if (!tpoint->tp_exchange_rate) {
            tpoint->tp_exchange_rate = 1;
        }

        // originator
        if ((cd->op_exchange_rate != 1)) {
            cd->op_price = cd->op_price / cd->op_exchange_rate;
        }

        // terminator
        if ((tpoint->tp_exchange_rate != 1)) {
            tpoint->tp_price = tpoint->tp_price / tpoint->tp_exchange_rate;
        }

        m2_log(M2_NOTICE, "Prices after convert to default currency: tp_rate: %f, tp_price: %f, op_rate: %f, op_price: %f\n", tpoint->tp_rate_after_exchange, tpoint->tp_price, cd->op_rate_after_exchange, cd->op_price);

        // do not update the same customer with the same price (for example: deduct 5 eur from customer A and give 5 eur to customer A)
        if (cd->op->user_id != tpoint->tp_user_id || (cd->op->user_id == tpoint->tp_user_id && cd->op_price != tpoint->tp_price)) {

            // update customer's balance

            if (cd->op->user_id >= 0 && cd->op_price != 0) {

                m2_log(M2_NOTICE, "User's balance will decrease by: %f\n", cd->op_price);

                if (balance_update_period == 0) {
                    if (non_blocking_balance) {
                        sprintf(query, "INSERT INTO user_balances(user_id, balance_delta) VALUES (%d, -%f) ON DUPLICATE KEY UPDATE balance_delta = balance_delta - %f", cd->op->user_id, cd->op_price, cd->op_price);
                    } else {
                        sprintf(query, "UPDATE users SET balance = balance - %f WHERE id = %d", cd->op_price, cd->op->user_id);
                    }

                    if (m2_mysql_query(cd, query, &connection)) {
                        return 1;
                    }

                    cd->user->balance -= cd->op_price;

                    mysql_connections[connection] = 0;
                } else {
                    m2_mutex_lock(USER_LOCK);
                    cd->user->balance -= cd->op_price;
                    cd->user->balance_diff -= cd->op_price;
                    m2_mutex_unlock(USER_LOCK);
                }
            }

            // update supplier's balance

            if (tpoint->tp_user_id >= 0 && tpoint->tp_price != 0) {

                m2_log(M2_NOTICE, "Supplier's balance will increase by: %f\n", tpoint->tp_price);

                if (balance_update_period == 0) {
                    if (non_blocking_balance) {
                        sprintf(query, "INSERT INTO user_balances(user_id, balance_delta) VALUES (%d, %f) ON DUPLICATE KEY UPDATE balance_delta = balance_delta + %f", tpoint->tp_user_id, tpoint->tp_price, tpoint->tp_price);
                    } else {
                        sprintf(query, "UPDATE users SET balance = balance + %f WHERE id = %d", tpoint->tp_price, tpoint->tp_user_id);
                    }

                    if (m2_mysql_query(cd, query, &connection)) {
                        return 1;
                    }

                    tpoint->user->balance += tpoint->tp_price;

                    mysql_connections[connection] = 0;
                } else {
                    m2_mutex_lock(USER_LOCK);
                    tpoint->user->balance += tpoint->tp_price;
                    tpoint->user->balance_diff += tpoint->tp_price;
                    m2_mutex_unlock(USER_LOCK);
                }
            }

        }

    } else {
        m2_log(M2_NOTICE, "Call will not be charged\n");
    }

    m2_log(M2_NOTICE, "cd->dialstatus: %s, cd->hangupcause: %d, cd->chan_name: %s\n", cd->dialstatus, cd->hangupcause, cd->chan_name);

    //----------------------- insert new record into CALLS table --------------------------------

    m2_log_cdr(cd, 1);

    return 0;

}

static void m2_calculate_call_price(int cdr_billsec, double rate, int min_time, int increment, double connection_fee, int *call_billsec, double *call_price) {

    // possible error fix
    if (increment < 1) increment = 1;

    // count seconds
    if (!(cdr_billsec % increment)) {
        *call_billsec = ceilf(cdr_billsec / increment) * increment;
    } else {
        *call_billsec = (ceilf(cdr_billsec / increment) + 1) * increment;
    }

    // min_time
    if (min_time && (*call_billsec < min_time)) {
        *call_billsec = min_time;
    }

    // count price
    *call_price = (rate **call_billsec) / 60;

    // add connection fee
    *call_price += connection_fee;

}


static int m2_log_cdr(calldata_t *cd, int main_cdr) {

    // do not log 'terminator' cdrs if call state is 'initiating call'
    // 'terminator' cdr should be generated when call state is 'routing call'
    // main cdr can be generated even if call state is 'initiating call'
    if (main_cdr == 0 && cd->call_state < M2_RINGING_STATE) {
        return 0;
    }

    //meter.calls_total++;

    // do not log if call is refused by cache and setting do_not_log_cached_cdrs = 1
    if (do_not_log_cached_cdrs && cd->cached_call) {
        m2_log(M2_NOTICE, "This CDR will not be logged to DB because do_not_log_cached_cdrs is on and call is refused by cache\n");
        return 0;
    }

    // do not log if setting is set not to log system cdrs
    if (do_not_log_system_cdrs && cd->hangupcause > 299) {
        m2_log(M2_NOTICE, "This CDR will not be logged to DB because do_not_log_system_cdrs is on and hangup cause [%d]\n", cd->hangupcause);
        return 0;
    }

    // do not log overboard CPS calls
    if (cd->hangupcause == 342) {
        m2_log(M2_NOTICE, "This CDR will not be logged to DB because CPS is too high [%d] and it can impact DB performance\n", meter.system_cps_last);
        return 0;
    }

    // do not log if call tracing enabled
    if (cd->call_tracing || cd->quality_routing_data) {
        return 0;
    }

    // should we log this cdr?
    if (do_not_log_failed_cdrs && strcmp(cd->dialstatus, "ANSWERED") != 0) {
        m2_log(M2_NOTICE, "Failed CDR will not be saved to database (do_not_log_failed_cdrs = 1)\n");
        return 0;
    }

    // should we log attempts?
    if (log_only_last_cdr && main_cdr == 0) {
        m2_log(M2_NOTICE, "Call attempts will not be saved to database (log_only_last_cdr = 1)\n");
        return 0;
    }

    if (!strcmp(cd->dialstatus, "ANSWERED")) {
        meter.answered_calls_total++;
    }

    int connection = 0;
    char query[10000] = "";
    int error = 0;
    int i = 0;

    tpoints_t *tpoint = NULL;
    if (cd->routing_table) {
        tpoint = cd->routing_table[cd->dial_count - 1].tpoint;
    }

    // data for originator
    int user_id = 0;
    int src_device_id = 0;
    int accountcode = 0;

    // data for terminator
    int dst_user_id = 0;
    int dst_device_id = 0;
    int dst_provider_id = 0;
    double dst_price = 0;
    double dst_rate = 0;
    int dst_billsec = 0;
    char dst_ipaddr[256] = "";
    char prefix[256] = "";
    char answer_time[64] = "";
    char end_time[64] = "";
    float pdd = 0;
    int async_cdr_insert_executed = 0;

    strlcpy(prefix, cd->op->prefix, sizeof(prefix));
    src_device_id = cd->op->id;

    // cdr data will depend on its type - main (user) cdr or terminator cdr
    // write user data to cdr only on last attempt
    if (main_cdr) {
        user_id = cd->op->user_id;
        accountcode = cd->op->id;
    }

    if (tpoint) {
        dst_device_id = tpoint->tp_id;
        dst_user_id = tpoint->tp_user_id;
        dst_provider_id = tpoint->tp_user_id;
        dst_price = tpoint->tp_price;
        dst_rate = tpoint->tp_rate_after_exchange;
        dst_billsec = tpoint->tp_billsec;
        pdd = tpoint->pdd;
        strlcpy(answer_time, tpoint->answer_time, 20);
        strlcpy(end_time, tpoint->end_time, 20);

        strlcpy(dst_ipaddr, tpoint->tp_ipaddr, sizeof(dst_ipaddr));
        if (strcmp(prefix_handle, "originator") != 0) {
            if (strcmp(prefix_handle, "terminator") == 0) {
                if (cd->terminator_prefix_saved == 0) {
                    strlcpy(prefix, tpoint->tp_prefix, sizeof(prefix));
                    cd->terminator_prefix_saved = 1;
                }
            }
            if (strlen(tpoint->tp_prefix) > strlen(prefix)) {
                strlcpy(prefix, tpoint->tp_prefix, sizeof(prefix));
            }
        }
    }

    // insert in batches
    // add new cdr to mysql query string
    m2_mutex_lock(MYSQL_BATCHES_LOCK);

    // !!!! Don't forget to update header file with query column changes !!!!!!

    if (cd->rn_number_used && strcmp(cd->dst, cd->original_dst)) {
        strcpy(cd->dst, cd->original_dst);
        m2_log(M2_DEBUG, "Reverting DST number back to original: %s\n", cd->original_dst);
    }

    calls_batch_counter++;
    sprintf(query, "('%s', '%s', '%d', '%d', '%f', '%f', '%s', '%d', '%s', '%d', '%f', '%f', '%d', "
        "'%f', '%f', '%d', '%d', '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%d'",
        cd->calldate, cd->original_src, cd->duration, cd->billsec, cd->real_billsec, cd->real_duration,
        cd->dialstatus, accountcode, cd->uniqueid_to_db, dst_device_id, cd->op_rate_after_exchange, cd->op_price, cd->op_billsec,
        dst_rate, dst_price, dst_billsec, user_id, dst_user_id, prefix, cd->hangupcause,
        cd->original_dst, cd->dst, cd->op->ipaddr, dst_ipaddr, src_device_id, cd->callerid, dst_provider_id, cd->server_id);

    // add additional data to cdr
    for (i = 0; i < additional_columns_count; i++) {
        if (additional_columns[i].add == 1) {
            char additional_col[256] = "";

            if (strcmp(additional_columns[i].name, "pdd") == 0) {
                sprintf(additional_col, ", '%f'", pdd);
            } else if (strcmp(additional_columns[i].name, "src_user_id") == 0) {
                sprintf(additional_col, ", '%d'", cd->op->user_id);
            } else if (strcmp(additional_columns[i].name, "terminated_by") == 0) {
                sprintf(additional_col, ", '%s'", cd->hangup_by);
            } else if (strcmp(additional_columns[i].name, "answer_time") == 0) {
                if (strlen(answer_time)) {
                    sprintf(additional_col, ", '%s'", answer_time);
                } else {
                    sprintf(additional_col, ", NULL");
                }
            } else if (strcmp(additional_columns[i].name, "end_time") == 0) {
                if (strlen(end_time)) {
                    sprintf(additional_col, ", '%s'", end_time);
                } else {
                    sprintf(additional_col, ", NULL");
                }
            } else if (strcmp(additional_columns[i].name, "originator_codec") == 0) {
                if (strlen(cd->originator_codec_used)) {
                    sprintf(additional_col, ", '%s'", cd->originator_codec_used);
                } else {
                    sprintf(additional_col, ", NULL");
                }
            } else if (strcmp(additional_columns[i].name, "terminator_codec") == 0) {
                if (strlen(cd->terminator_codec_used)) {
                    sprintf(additional_col, ", '%s'", cd->terminator_codec_used);
                } else {
                    sprintf(additional_col, ", NULL");
                }
            } else if (strcmp(additional_columns[i].name, "pai") == 0) {
                if (strlen(cd->originator_pai_number)) {
                    sprintf(additional_col, ", '%s'", cd->originator_pai_number);
                } else {
                    sprintf(additional_col, ", NULL");
                }
            }

            strcat(query, additional_col);
        }
    }

    strcat(query, "),");
    strlcat(calls_batch_buffer, query, sizeof(calls_batch_buffer));

    m2_log(M2_DEBUG, "Query added to the batch %d/%d\n", calls_batch_counter, cdr_batch_size);

    // flush calls to database if batch is full
    if (calls_batch_counter == cdr_batch_size) {

        m2_log(M2_DEBUG, "Flushing CDRs to the Database (Batch full)\n");

        // remove last ',' separator
        calls_batch_buffer[strlen(calls_batch_buffer) - 1] = 0;


        if (async_cdr_insert) {
            async_cdr_insert_executed = 1;
            m2_async_cdr_insert(cd, 1, calls_batch_buffer);
        } else {

            meter.cdr_insert_count_start++;
            double start_time = m2_get_current_time();


            if (m2_mysql_query(NULL, calls_batch_buffer, &connection)) {
                error = 1;
            }

            mysql_connections[connection] = 0;

            calls_batch_counter = 0;
            memset(calls_batch_buffer, 0, sizeof(calls_batch_buffer));
            // initialize query buffer
            sprintf(calls_batch_buffer, "%s VALUES ", calls_insert_fields);

            // saving metering stats
            double run_time = m2_get_current_time() - start_time;
            meter.cdr_insert_time += run_time;
            meter.cdr_insert_count++;
            if (run_time > meter.cdr_insert_time_max) meter.cdr_insert_time_max = run_time;

        }


    }

    if (!async_cdr_insert_executed) m2_mutex_unlock(MYSQL_BATCHES_LOCK);

    return error;

}


/*

    Periodically flush calls to database

*/


static void *m2_calls_batch_timer() {

    cdr_batch_timer = 0;
    batch_timer_running = 1;

    while(1) {

        sleep(1);
        cdr_batch_timer++;

        // every X seconds flush calls to database
        if (cdr_batch_timer == cdr_flush_time) {
            m2_flush_calls_to_database(1);
            cdr_batch_timer = 0;
        }

        if (stop_batch_timer) break;

    }

    batch_timer_running = 0;
    pthread_exit(NULL);

}


/*

    Flush calls to database

*/


static int m2_flush_calls_to_database(int lock) {

    // this variable is used by freeradius module's log function
    calldata_t *cd = NULL;

    int async_cdr_insert_executed = 0;
    int connection = 0;
    int error = 0;

    // we are dealing with global variables so we should lock this section

    if (lock) m2_mutex_lock(MYSQL_BATCHES_LOCK);

    // check if we have accounting calls
    if (calls_batch_counter > 0) {

        m2_log(M2_DEBUG, "Flushing CDRs to the Database (Time)\n");

        calls_batch_buffer[strlen(calls_batch_buffer) - 1] = 0; // remove last comma separator

        if (async_cdr_insert) {
            async_cdr_insert_executed = 1;
            m2_async_cdr_insert(NULL, lock, calls_batch_buffer);
        } else {

            meter.cdr_insert_count_start++;
            double start_time = m2_get_current_time();

            if (m2_mysql_query(NULL, calls_batch_buffer, &connection)) {
                error = 1;
            }

            // reset variables
            calls_batch_counter = 0;
            memset(calls_batch_buffer, 0, sizeof(calls_batch_buffer));
            sprintf(calls_batch_buffer, "%s VALUES ", calls_insert_fields);

            mysql_connections[connection] = 0;

            // saving metering stats
            double run_time = m2_get_current_time() - start_time;
            meter.cdr_insert_time += run_time;
            meter.cdr_insert_count++;
            if (run_time > meter.cdr_insert_time_max) meter.cdr_insert_time_max = run_time;

        }

    }

    // If async_cdr_insert is enabled, then MYSQL_BATCHES_LOCK will be unlocked in m2_async_cdr_insert_thread
    if (lock && async_cdr_insert_executed == 0) m2_mutex_unlock(MYSQL_BATCHES_LOCK);
    return error;

}


/*
    Replace ' with `
*/


static void m2_clean_callerid(char *callerid) {

    int i = 0;
    int length = strlen(callerid);

    for (i = 0; i < length; i++) {
        if (callerid[i] == '\'') {
            callerid[i] = '`';
        }
    }

}


/*
    Create thread which will be used to insert CDRs
*/


static void m2_async_cdr_insert(calldata_t *cd, int locked, char *query) {

    pthread_t async_cdr_insert_thread;
    pthread_attr_t async_cdr_insert_attr;

    m2_log(M2_DEBUG, "Creating CDR insert thread\n");

    async_cdr_insert_args_t *args = (async_cdr_insert_args_t *)malloc(sizeof(async_cdr_insert_args_t));
    args->locked = locked;
    args->query = query;

    pthread_attr_init(&async_cdr_insert_attr);
    pthread_attr_setdetachstate(&async_cdr_insert_attr, PTHREAD_CREATE_DETACHED);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if (pthread_create(&async_cdr_insert_thread, &async_cdr_insert_attr, m2_async_cdr_insert_thread, args)) {
        free(args);
    }

    pthread_attr_destroy(&async_cdr_insert_attr);

}


/*
    Handle async CDR insert
*/


static void *m2_async_cdr_insert_thread(void *args_param) {

    meter.cdr_insert_count_start++;
    double start_time = m2_get_current_time();

    int connection = 0;
    char local_query[80000] = "";
    async_cdr_insert_args_t *args = args_param;

    strcpy(local_query, args->query);

    // reset variables
    calls_batch_counter = 0;
    memset(calls_batch_buffer, 0, sizeof(calls_batch_buffer));
    sprintf(calls_batch_buffer, "%s VALUES ", calls_insert_fields);

    // Once we have copied global query to our local query, unlock BATCH lock
    if (args->locked) {
        m2_mutex_unlock(MYSQL_BATCHES_LOCK);
    }

    if (!m2_mysql_query(NULL, local_query, &connection)) {
        mysql_connections[connection] = 0;
    }

    free(args);

    // saving metering stats
    double run_time = m2_get_current_time() - start_time;
    meter.cdr_insert_time += run_time;
    meter.cdr_insert_count++;
    if (run_time > meter.cdr_insert_time_max) meter.cdr_insert_time_max = run_time;

    pthread_exit(NULL);

}
