
static void m2_set_hangupcause(calldata_t *cd, int hgc) {

    cd->hangupcause = hgc;
    strlcpy(cd->dialstatus, "FAILED", sizeof(cd->dialstatus));

    int response_hgc = -1;

    // values from m2.conf
    response_hgc = hgc_mapping[hgc];

    // special case for 318 hgc, when codecs are not allowed
    if (hgc == 318) {
        response_hgc = 88;
    }

    if (cd->op != NULL && strlen(cd->op->hgc_mapping)) {
        int code = -1;
        char buffer[30] = "";
        sprintf(buffer, "%d=", hgc);
        char *ptr = strstr(cd->op->hgc_mapping, buffer);
        if (ptr) {
            sscanf(ptr, "%d=%d", &code, &code);
            if (code > -1) {
                response_hgc = code;
            }
        }
    }

    if (response_hgc > -1 && cd->system_hangup_reason == M2_SYSTEM_HANGUP_NOT_REQUESTED) {
        if (cd->radius_auth_request) {
            char hgc_string[256] = "";
            sprintf(hgc_string, "%d", response_hgc);
            m2_radius_add_attribute_value_pair(cd, "m2_hangupcause", hgc_string, M2_CISCO_AVP);
        } else {
            m2_log(M2_WARNING, "Cannot add m2_hangupcause, because cd->radius_auth_request is null\n");
        }
    }

}


/*
    Limit up to X calls per Y seconds
*/


static int m2_check_cps(int accountcode, calldata_t *cd) {

    int found = 0;
    int i = 0;

    // we are dealing with global variables, we should lock this function
    m2_mutex_lock(CPS_LOCK);

    // find device index by ID
    for (i = 0; i < cps_count; i++) {
        // if device was found, break from loop
        if (cps[i].accountcode == accountcode) {
            found = 1;
            break;
        }
    }

    // if device was found
    if (found) {

        m2_log(M2_DEBUG, "Found CPS for OP [%d], period = %d, limit = %d\n", cps[i].accountcode, cps[i].cps_period, cps[i].cps_limit);

        // check if cps is unlimited
        if (cps[i].cps_period == 0 || cps[i].cps_limit == 0) {
            // unlimited
            m2_mutex_unlock(CPS_LOCK);
            return 0;
        }

        // this counter stores the number of calldates that fall under CPS limitation
        int cps_counter = 0;

        // get current date
        struct timeval current_date;
        gettimeofday(&current_date, NULL);

        // convert seconds to microseconds
        unsigned long int t1us = current_date.tv_sec * 1000000 + current_date.tv_usec;

        // check if current calldate falls under CPS limitation
        time_values_t *start = cps[i].time_value;       // save the beginning of the list
        time_values_t *last = NULL;                     // address of the las date that is accepted
        time_values_t *next = NULL;                     // address of the next calldate value

        while (cps[i].time_value) {

            // save the address of the next calldate value (in case we have to free this one)
            next = cps[i].time_value->next;

            // convert seconds to microseconds
            unsigned long int t2us = cps[i].time_value->calldate.tv_sec * 1000000 + cps[i].time_value->calldate.tv_usec;

            // check if this call is in the cps limit period
            if (abs(t2us - t1us) <= cps[i].cps_period * 1000000) {
                // if so, save this address
                last = cps[i].time_value;
                // and increase counter
                cps_counter++;
            } else {
                // if it doesn't, free allocated memory for this calldate
                if(cps_counter > 0) {
                    last->next = NULL;
                    free(cps[i].time_value);
                }
            }

            // get next calldate value
            cps[i].time_value = next;
        }

        // restore the beginning of the list
        cps[i].time_value = start;

        // check cps limit
        if (cps_counter <= cps[i].cps_limit - 1) {

            // limit is not reached, call can pass
            // add current calldate to dynamic list of other calldate
            time_values_t *time_value = (time_values_t *)malloc(sizeof(time_values_t));
            gettimeofday(&time_value->calldate, NULL);
            time_value->next = cps[i].time_value_head;
            cps[i].time_value = time_value;
            cps[i].time_value_head = time_value;

        } else {

            // limit is reached, call cannot pass
            m2_log(M2_WARNING, "WARNING: CPS limit is reached! (OP [%d], period = %d s, call limit = %d)\n", accountcode, cps[i].cps_period, cps[i].cps_limit);
            // unlock function
            m2_mutex_unlock(CPS_LOCK);
            return 1;

        }
    }

    // unlock function
    m2_mutex_unlock(CPS_LOCK);

    return 0;
}

/*
    Update CPS data at every call
*/

static void m2_update_cps_data(int accountcode, int cps_limit, int cps_period, calldata_t *cd) {

    if (cps_limit == 0 || cps_period == 0) {
        return;
    }

    int i;
    int found = 0;

    // we are dealing with global variables, we should lock this function
    m2_mutex_lock(CPS_LOCK);

    for (i = 0; i < cps_count; i++) {
        // if device was found, break from loop
        if (cps[i].accountcode == accountcode) {
            found = 1;
            break;
        }
    }

    // if device is in the dynamic list, then update its data

    if (found) {

        m2_log(M2_DEBUG, "Updating CPS for OP [%d], cps_period = %d, cps_limit = %d\n", accountcode, cps_period, cps_limit);
        if (cps_limit < 0) cps_limit = 0;
        if (cps_period < 0) cps_period = 0;

        cps[i].cps_limit = cps_limit;
        cps[i].cps_period = cps_period;

    } else {

        // skip if necessary
        if (cps_limit == 0 || cps_period == 0) {
            m2_mutex_unlock(CPS_LOCK);
            return;
        }

        m2_log(M2_DEBUG, "Inserting new CPS for OP [%d], cps_period = %d, cps_limit = %d\n", accountcode, cps_period, cps_limit);

        // if this is the first time someone is using this device
        // add cps data to the dynamic list

        cps = realloc(cps, (cps_count + 1) * sizeof(cps_control_t));

        // save cps data
        if (cps_limit < 0) cps_limit = 0;
        if (cps_period < 0) cps_period = 0;

        cps[i].cps_limit = cps_limit;
        cps[i].cps_period = cps_period;

        // save device id
        cps[cps_count].accountcode = accountcode;

        // add current calldate to dynamic list of other calldate
        time_values_t *time_value = (time_values_t *)malloc(sizeof(time_values_t));
        time_value->calldate.tv_sec = 0;
        time_value->calldate.tv_usec = 0;
        time_value->next = NULL;
        cps[cps_count].time_value = time_value;
        cps[cps_count].time_value_head = time_value;

        // increase device count
        cps_count++;
    }

    m2_mutex_unlock(CPS_LOCK);

}

/*
    Free dynamically allocated memory for cps
*/

static void m2_free_cps_data() {

    if (cps_count > 0) {
        int i = 0;

        for (i = 0; i < cps_count; i++) {
            time_values_t *current_timeval = NULL, *next_timeval = NULL;

            current_timeval = cps[i].time_value;

            while (current_timeval) {
                next_timeval = current_timeval->next;
                free(current_timeval);
                current_timeval = next_timeval;
            }
        }

        free(cps);
    }

}


/*
    Get random IP address from IP subnet
*/


static void m2_get_random_ippaddr_from_subnet(calldata_t *cd, char *cidr, char *ipaddr) {

    char *cidr_ptr = NULL;

    // check if strings exist
    if (!cidr && !ipaddr && !strlen(cidr)) return;

    // check if CIDR notation is valid
    cidr_ptr = strstr(cidr, "/");
    if (!cidr_ptr) {
        m2_log(M2_ERROR, "CIDR notation is not valid\n");
        return;
    } else {

        // check if subnet length is correct
        if (strlen(cidr_ptr) < 2 || strlen(cidr_ptr) > 3) {
            m2_log(M2_ERROR, "CIDR notation is not valid\n");
            return;
        }

        // skip slash
        cidr_ptr++;

        // check if subnet is number
        int i;
        for (i = 0; i < strlen(cidr_ptr); i++) {
            if (!isdigit(*(cidr_ptr + i))) {
                printf("CIDR notation is not valid\n");
                return;
            }
        }

        int network_bits = atoi(cidr_ptr);

        // check if there are valid ip addreses or ip range is sensible
        // min 2 valid ip addresses, max 262k
        if (network_bits > 30 || network_bits < 4) {
            m2_log(M2_ERROR, "Subnet range is invalid: %d\n", network_bits);
            strncpy(ipaddr, cidr, strlen(cidr) - strlen(cidr_ptr) - 1);
            return;
        }

        uint32_t mask = 0xFFFFFFFF << (32 - network_bits);

        int total_addreses = (int)pow((double)2, (32 - network_bits)) - 2;

        char tmp_cidr[128] = "";
        strncpy(tmp_cidr, cidr, strlen(cidr) - strlen(cidr_ptr) - 1);

        int ipbyte1, ipbyte2, ipbyte3, ipbyte4;
        sscanf(tmp_cidr, "%d.%d.%d.%d", &ipbyte1, &ipbyte2, &ipbyte3, &ipbyte4);
        uint32_t ipaddr_int = (ipbyte4 | ipbyte3 << 8 | ipbyte2 << 16 | ipbyte1 << 24);

        srand(time(NULL));
        int rnd = random() % total_addreses + 1;

        uint32_t random_ip = (ipaddr_int & mask) + rnd;

        sprintf(ipaddr, "%i.%i.%i.%i", (random_ip >> 24) & 0xFF, (random_ip >> 16) & 0xFF, (random_ip >> 8) & 0xFF, random_ip & 0xFF);

    }

}


/*
    Get random IP address from IP range
*/


static void m2_get_random_ippaddr_from_range(calldata_t *cd, char *range, char *ipaddr) {

    char range_string[256] = "";
    char *range_ptr = NULL;

    if (range) {
        strlcpy(range_string, range, sizeof(range_string));
    }

    // check if strings exist
    if (!ipaddr && !strlen(range)) return;

    // check if range notation is valid
    range_ptr = strstr(range, "-");
    if (!range_ptr) {
        m2_log(M2_ERROR, "Range notation is not valid\n");
        return;
    } else {

        char network[128] = "";

        strlcpy(network, range_string, sizeof(network));

        int range_start;
        int range_end;
        int tmp;
        sscanf(network, "%d.%d.%d.%d-%d", &tmp, &tmp, &tmp, &range_start, &range_end);

        int total_addreses = range_end - range_start + 1;

        srand(time(NULL));
        int random_offset = random() % total_addreses;
        int range_rand = range_start + random_offset;

        // find last octet
        strcpy(ipaddr, network);
        char *last_octet_ptr = strrchr(ipaddr, '.');
        if (last_octet_ptr) {
            *last_octet_ptr = '\0';
            char tmp_buffer[32] = "";
            sprintf(tmp_buffer, ".%d", range_rand);
            strcat(ipaddr, tmp_buffer);
        }

    }

}


/*
    Split number into parts
*/


static void m2_format_prefix_sql(char *prefixes, const char *number) {

    char buffer[256] = "";
    int i = 0;

    memset(buffer, '\0', sizeof(buffer));
    memset(prefixes, '\0', 9000);

    for(i = 0; i < strlen(number); i++) {

        strlcat(prefixes, "'", 9000);
        strncpy(buffer, number, i + 1);
        strlcat(prefixes, buffer, 9000);
        strlcat(prefixes, "'", 9000);
        if( i < (strlen(number) - 1)) strcat(prefixes, ",");
        memset(buffer, '\0', sizeof(buffer));

    }

}

static void m2_change_callstate(calldata_t *cd, m2_call_state_t call_state) {

    cd->call_state = call_state;

    m2_log(M2_DEBUG, "Changed call state to: %s\n", call_state_str[call_state] == NULL ? "UNKNOWN" : call_state_str[call_state]);

}

static void m2_get_callerid_from_number_pool(calldata_t *cd, char *callerid, int callerid_len, int number_pool_id, char *type, int deviation) {

    MYSQL_RES *result = NULL;
    MYSQL_ROW row;
    int connection = 0;
    char sqlcmd[1024] = "";
    char pseudorandom_sql[512] = "";
    long long int offset = 0;
    unsigned long long int number_id = 0;

    if (strcmp(type, "pseudorandom") == 0) {
        unsigned long long int min_counter = 0;
        unsigned long long int max_counter = 0;

        sprintf(sqlcmd, "SELECT MIN(counter) FROM numbers WHERE number_pool_id = %d", number_pool_id);

        if (m2_mysql_query(cd, sqlcmd, &connection)) {
            return;
        }

        result = mysql_store_result(&mysql[connection]);
        mysql_connections[connection] = 0;

        if (result) {
            while ((row = mysql_fetch_row(result))) {
                if (row[0]) {
                    min_counter = atoll(row[0]);
                }
            }

            mysql_free_result(result);
        }

        if (deviation == 0) {
            max_counter = min_counter;
        } else {
            max_counter = (deviation + min_counter) - 1;
        }

        sprintf(pseudorandom_sql, " AND counter BETWEEN %lld AND %lld", min_counter, max_counter);
    }

    sprintf(sqlcmd, "SELECT count(id) FROM numbers WHERE number_pool_id = %d%s", number_pool_id, pseudorandom_sql);

    // get total numbers for that number pool
    if (!m2_mysql_query(cd, sqlcmd, &connection)) {

       // query succeeded, get results and mark connection as available
       result = mysql_store_result(&mysql[connection]);
       mysql_connections[connection] = 0;

       if (result) {
            while ((row = mysql_fetch_row(result))) {
                if (row[0]) offset = atoll(row[0]);
            }
            mysql_free_result(result);
        }
    }

    // handle 'no numbers in this number pool' situation
    if (offset == 0) {
        return;
    }

    // randomize offset
    srand(time(NULL));
    long long int random_offset = random() % offset;

    sprintf(sqlcmd, "SELECT number, id FROM numbers WHERE number_pool_id = %d%s LIMIT %lli, 1", number_pool_id, pseudorandom_sql, random_offset);

    // get random number from pool
    if (!m2_mysql_query(cd, sqlcmd, &connection)) {

        // query succeeded, get results and mark connection as available
        result = mysql_store_result(&mysql[connection]);
        mysql_connections[connection] = 0;

        if (result) {
            while ((row = mysql_fetch_row(result))) {
                if (row[0]) {
                    strlcpy(callerid, row[0], callerid_len - 1);
                    m2_log(M2_NOTICE, "Random CallerID from number pool: %s\n", callerid);
                }
                if (row[1]) {
                    number_id = atoll(row[1]);
                }
            }
            mysql_free_result(result);
        }
    }

    if (strlen(callerid) && strcmp(type, "pseudorandom") == 0) {
        sprintf(sqlcmd, "UPDATE numbers SET counter = counter + 1 WHERE id = %lld", number_id);

        if (!m2_mysql_query(cd, sqlcmd, &connection)) {
            mysql_connections[connection] = 0;
        }
    }

}


static void _m2_log(int type, calldata_t *cd, char *msg) {

    if (!strlen(msg)) return;

    char uniqueid[256] = "";

    // if we have calldata, then use it's uniqueid to identify call in message log
    // but use only part of uniqueid, because it is too long and last part of uniqueid doesn't change often
    if (cd != NULL) {
        if (cd->uniqueid != NULL) {
            if (strlen(cd->uniqueid)) {
                sprintf(uniqueid, "[%s", cd->uniqueid);
                strlcat(uniqueid, "]", sizeof(uniqueid));
            }
        }
    }

    // no uniqueid in log for development (to save screen space)
    if (no_uniqueid_in_log){
        strcpy(uniqueid, "");
    }

    if (cd != NULL && cd->call_tracing) {
        strlcpy(uniqueid, "m2_call_tracing", sizeof(uniqueid));
    }

    if (type == 1) {
        if (SHOW_NOTICE) radlog(L_INFO, " [NOTICE] %s %s", uniqueid, msg);
    } else if (type == 2) {
        if (SHOW_WARNING) radlog(L_INFO, "[WARNING] %s %s", uniqueid, msg);
    } else if (type == 3) {
        if (SHOW_ERROR) radlog(L_INFO, "  [ERROR] %s %s", uniqueid, msg);
    } else if (type == 4) {
        if (SHOW_DEBUG) radlog(L_INFO, "  [DEBUG] %s %s", uniqueid, msg);
    }

    if (cd != NULL && cd->call_tracing && cd->quiet_call_tracing == 0) {
        char current_date[20] = "";
        char filename[256] = "";
        FILE *fp = NULL;
        time_t t;
        struct tm tmp;

        t = time(NULL);
        localtime_r(&t, &tmp);
        strftime(current_date, sizeof(current_date), DATETIME_FORMAT, &tmp);

        sprintf(filename, "/tmp/m2/m2_call_tracing/%s.m2_call_trace", cd->uniqueid);
        fp = fopen(filename, "a+");

        if (fp) {
            if (type == 1) {
                fprintf(fp, "%s  [NOTICE] %s", current_date, msg);
            } else if (type == 2) {
                fprintf(fp, "%s [WARNING] %s", current_date, msg);
            } else if (type == 3) {
                fprintf(fp, "%s   [ERROR] %s", current_date, msg);
            } else if (type == 4) {
                fprintf(fp, "%s   [DEBUG] %s", current_date, msg);
            }
            fclose(fp);
        }
    }

}

static void m2_mutex_lock(int lock) {

/*
    if (lock == 1) {


    } else
*/

    if (lock == 2) {
        pthread_mutex_lock(&mysql_mutex);
    } else if (lock == 3) {
        pthread_mutex_lock(&file_mutex);
    } else if (lock == 4) {
        pthread_mutex_lock(&cps_mutex);
    } else if (lock == 5) {
        pthread_mutex_lock(&mysql_batches_mutex);
    } else if (lock == 6) {
        pthread_mutex_lock(&quality_table_mutex);
    } else if (lock == 7) {
        pthread_mutex_lock(&non_blocking_balance_mutex);
    } else if (lock == 8) {
        //pthread_mutex_lock(&metering_mutex);
    } else if (lock == 9) {
        pthread_mutex_lock(&hgc_cache_mutex);
    } else if (lock == 10) {
        pthread_mutex_lock(&tid_cache_mutex);
    } else if (lock == 11) {
        pthread_mutex_lock(&connp_list_mutex);
    } else if (lock == 12) {
        pthread_mutex_lock(&dp_list_mutex);
    } else if (lock == 13) {
        pthread_mutex_lock(&dp_cache_mutex);
    } else if (lock == 14) {
        pthread_mutex_lock(&tp_rates_mutex);
    } else if (lock == 15) {
        pthread_mutex_lock(&user_mutex);
    } else if (lock == 16) {
        pthread_mutex_lock(&counters_mutex);
    } else if (lock == 17) {

        meter.acalock_count_start++;
        double start_time = m2_get_current_time();

        pthread_mutex_lock(&ac_array_mutex);

        // saving metering stats
        double run_time = m2_get_current_time() - start_time;
        meter.acalock_time += run_time;
        meter.acalock_count++;
        if (run_time > meter.acalock_time_max) meter.acalock_time_max = run_time;
        if (run_time > meter.acalock_time_maxps) meter.acalock_time_maxps = run_time;
    } else if (lock == 18) {
        pthread_mutex_lock(&ac_hang_mutex);
    }

}

static void m2_mutex_unlock(int lock) {

/*
    if (lock == 1) {
        pthread_mutex_unlock(&activecalls_mutex);
    } else
*/

    if (lock == 2) {
        pthread_mutex_unlock(&mysql_mutex);
    } else if (lock == 3) {
        pthread_mutex_unlock(&file_mutex);
    } else if (lock == 4) {
        pthread_mutex_unlock(&cps_mutex);
    } else if (lock == 5) {
        pthread_mutex_unlock(&mysql_batches_mutex);
    } else if (lock == 6) {
        pthread_mutex_unlock(&quality_table_mutex);
    } else if (lock == 7) {
        pthread_mutex_unlock(&non_blocking_balance_mutex);
    } else if (lock == 8) {
        //pthread_mutex_unlock(&metering_mutex);
    } else if (lock == 9) {
        pthread_mutex_unlock(&hgc_cache_mutex);
    } else if (lock == 10) {
        pthread_mutex_unlock(&tid_cache_mutex);
    } else if (lock == 11) {
        pthread_mutex_unlock(&connp_list_mutex);
    } else if (lock == 12) {
        pthread_mutex_unlock(&dp_list_mutex);
    } else if (lock == 13) {
        pthread_mutex_unlock(&dp_cache_mutex);
    } else if (lock == 14) {
        pthread_mutex_unlock(&tp_rates_mutex);
    } else if (lock == 15) {
        pthread_mutex_unlock(&user_mutex);
    } else if (lock == 16) {
        pthread_mutex_unlock(&counters_mutex);
    } else if (lock == 17) {
        pthread_mutex_unlock(&ac_array_mutex);
    } else if (lock == 18) {
        pthread_mutex_unlock(&ac_hang_mutex);
    }

}

/*
    Read channel variables and store them in the calldata structure
*/


static int m2_read_variables(REQUEST *request, calldata_t *cd) {

    // get calldate
    struct tm *tmm;
    time_t t;
    t = time(NULL);
    tmm = localtime(&t);
    strftime(cd->date, sizeof(cd->date), DATE_FORMAT, tmm);
    strftime(cd->time, sizeof(cd->time), TIME_FORMAT, tmm);
    sprintf(cd->calldate, "%s %s", cd->date, cd->time);
    char ipaddr_from_calltracing[256] = "";
    char op_port_str[10] = "";
    char server_id_str[10] = "";
    char proxy_op_ip[256] = "";
    char proxy_op_port_str[10] = "";
    int proxy_op_port = 0;
    struct timeb tp;
    ftime(&tp);

    cd->start_time = tp.time + (tp.millitm / 1000.0);
    cd->timestamp = time(NULL);

    // check if call was made during a free day or a work day
    // by default, cd->daytype is WD
    strlcpy(cd->daytype, "WD", sizeof(cd->daytype));

    if (tmm->tm_wday == 0 || tmm->tm_wday == 6) {
        strlcpy(cd->daytype, "FD", sizeof(cd->daytype));
    }

    // default unset m2 hangupcause
    cd->hangupcause = -1;

    // default server_id
    cd->server_id = 1;

    // Standard radius attributes
    m2_radius_get_attribute_value_by_name(request, "h323-remote-address", ipaddr_from_calltracing, sizeof(ipaddr_from_calltracing), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(request, "User-Name", cd->op->ipaddr, sizeof(cd->op->ipaddr), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(request, "Calling-Station-Id", cd->src, sizeof(cd->src), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(request, "Called-Station-Id", cd->dst, sizeof(cd->dst), M2_STANDARD_AVP);
    m2_radius_get_attribute_value_by_name(request, "call-id", cd->uniqueid, sizeof(cd->uniqueid), M2_CISCO_AVP);

    // Custom radius attributes
    m2_radius_get_attribute_value_by_name(request, "freeswitch-callerid-name", cd->callerid, sizeof(cd->callerid), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-src-channel", cd->chan_name, sizeof(cd->chan_name), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-src-port", op_port_str, sizeof(op_port_str), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-codec-list", cd->op->codec_list, sizeof(cd->op->codec_list), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-server-id", server_id_str, sizeof(server_id_str), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-invite-destination", cd->invite_dst, sizeof(cd->invite_dst), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-proxy-op-ip", proxy_op_ip, sizeof(proxy_op_ip), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-proxy-op-port", proxy_op_port_str, sizeof(proxy_op_port_str), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-pai", cd->originator_pai, sizeof(cd->originator_pai), M2_CISCO_AVP);
    m2_radius_get_attribute_value_by_name(request, "freeswitch-lnp", cd->lnp, sizeof(cd->lnp), M2_CISCO_AVP);

    // Special case. Do not change 33
    // database field calls.uniqueid is 33 char length (leftover from MOR system) but real unqiueid is longer
    // usually there are no problems when we save a bit shorter uniqueid in database
    strncpy(cd->uniqueid_to_db, cd->uniqueid, 33);

    if (strlen(proxy_op_port_str)) {
        proxy_op_port = atoi(proxy_op_port_str);
    }

    if (strlen(server_id_str)) {
        cd->server_id = atoi(server_id_str);
    }

    if (strlen(op_port_str)) {
        cd->op->port = atoi(op_port_str);
    }

    if (strlen(cd->originator_pai)) {
        m2_parse_header_number_part(cd->originator_pai, cd->originator_pai_number, sizeof(cd->originator_pai_number));
    }

    m2_filter_string_strict(cd->src);
    m2_filter_string(cd->callerid);
    m2_filter_string(cd->chan_name);
    m2_filter_string_strict(cd->invite_dst);
    m2_filter_string_strict(cd->dst);
    m2_filter_string_strict(cd->originator_pai);

    if (strcmp(cd->op->ipaddr, proxy_ipaddr) == 0 && strlen(proxy_ipaddr)) {
        m2_log(M2_NOTICE, "Call comes from proxy server %s\n", cd->op->ipaddr);
        if (strlen(proxy_op_ip)) {
            strcpy(cd->op->ipaddr, proxy_op_ip);
            cd->op->port = proxy_op_port;
            m2_log(M2_NOTICE, "OP IP: %s, port: %d\n", proxy_op_ip, proxy_op_port);
        } else {
            m2_log(M2_ERROR, "OP IP is unknown, check if x-M2-Originator-ip header is present!\n");
            m2_set_hangupcause(cd, 341);
            return 1;
        }
    }

    if (!strlen(cd->callerid)) {
        strlcpy(cd->callerid, cd->src, sizeof(cd->callerid));
        strlcpy(cd->callerid_number, cd->src, sizeof(cd->callerid_number));
    } else {
        char tmp_buffer[128] = "";
        strlcpy(tmp_buffer, cd->callerid, sizeof(tmp_buffer));
        strlcpy(cd->callerid_name, cd->callerid, sizeof(cd->callerid_name));
        strlcpy(cd->callerid_number, cd->src, sizeof(cd->callerid_number));
        sprintf(cd->callerid, "\"%s\" <%s>", tmp_buffer, cd->src);
    }

    // clean callerid
    m2_clean_callerid(cd->callerid);
    m2_clean_callerid(cd->callerid_name);

    // save original destination and source
    strlcpy(cd->original_dst, cd->dst, sizeof(cd->original_dst));
    strlcpy(cd->original_src, cd->src, sizeof(cd->original_src));

    if (strstr(cd->op->ipaddr, "device_id_")) {
        cd->call_tracing_accountcode = atoi(cd->op->ipaddr + strlen("device_id_"));
        strlcpy(cd->op->ipaddr, ipaddr_from_calltracing, sizeof(cd->op->ipaddr));
    }

    m2_log(M2_NOTICE, "Received data [%s]: host: %s, port: %d, src: %s, dst: %s, callerid: %s, calldate: %s, uniqueid: %s, server_id: %d\n",
        cd->chan_name, cd->op->ipaddr, cd->op->port, cd->src, cd->dst, cd->callerid, cd->calldate, cd->uniqueid, cd->server_id);

    // LNP
    m2_handle_lnp(cd);

    if (strcmp(cd->chan_name, "m2_call_trace") == 0) {
        cd->call_tracing = 1;
        strcpy(cd->invite_dst, cd->dst);
        m2_log(M2_NOTICE, "This is call tracing!\n");
    }

    if (strcmp(cd->chan_name, "m2_quality_routing_data") == 0) {
        cd->quality_routing_data = 1;
        int dp_id = atoi(cd->src);
        int qa_id = atoi(cd->dst);
        char dst[256] = "";
        strlcpy(dst, cd->op->ipaddr, sizeof(dst));
        m2_show_quality_routing_data(cd, dp_id, qa_id, dst);
        return 1;
    }

    if (!strlen(cd->op->ipaddr)) {
        m2_log(M2_ERROR, "Host can not be empty!\n");
        m2_set_hangupcause(cd, 300);
        return 1;
    }

    // Checking IP in the cache for 301 HGC
    cd->cached_call = 0;
    int value = m2_hgc_cache_get_arr(cd);
    if (value) {
        m2_log(M2_NOTICE, "HGC CACHE: [%s:%i] tech_prefix [%s] value [%i] found in the cache\n", cd->op->ipaddr, cd->op->port, cd->op->tech_prefix, value);
        m2_set_hangupcause(cd, value);
        cd->cached_call = 1;                                  // marking that this call was found in the cache
        return 1;
    }

    if (!strlen(cd->dst)) {
        m2_log(M2_ERROR, "Destination can not be empty!\n");
        m2_set_hangupcause(cd, 336);
        return 1;
    }


    // The goal with this code is to survive high CPS spikes.
    // We delay the call processing to the DB because currently our bottleneck is the DB.
    // Adding 1 second to PDD is wrong on all levels but it should help to spread the load on the DB.
    // If after 1 s there is still a huge load - we simply drop the excesive calls thus allowing the system to process other calls.
    // If CPS is higher 2 times than CPS_LIMIT - we will drop such calls at once, because next second can handle max CPS_LIMIT calls in the best case (with 0 new CPS next second)


    // counting if cps served by DB (cps after cache hits) is not higher than the limit
    if (meter.system_cps_current - meter.cache_hits_current >= DB_CPS_LIMIT + 1) {

        // if we have 2x times more CPS than we think we can handle - there is no point delaying these calls, they must be dropped
        if ((meter.system_cps_current - meter.cache_hits_current) >= DB_CPS_LIMIT * 2) {
            m2_log(M2_WARNING, "Real CPS Limit reached [sy %d, db %d]! Call aborting. (CPS_LIMIT x2)\n", meter.system_cps_current, meter.system_cps_current - meter.cache_hits_current);
            m2_set_hangupcause(cd, 342);
            meter.hgc342_dropped_calls++;
            return 1;
        }

        // Delaying the call processing (increasing PDD, sorry...) with the hope CPS will be lower after 1 s
        m2_log(M2_WARNING, "Delaying call processing because of high CPS [sy %d, db %d] (PDD +1s)\n", meter.system_cps_current, meter.system_cps_current - meter.cache_hits_current);

        //meter.system_cps_current--;    // decreasing the counter because this call is delayed - no need, it will mess up x2 calculations
        meter.hgc342_delayed_calls++;
        sleep(1);                      // this is so so wrong... (but still better than to completely dropping the call)
        meter.system_cps_current++;    // increasing the counter because this call will process in the current second


        // Rechecking cps
        if ((meter.system_cps_current - meter.cache_hits_current) >= DB_CPS_LIMIT + 1) {

            m2_log(M2_WARNING, "Real CPS Limit reached [sy %d, db %d]! Call aborting.\n", meter.system_cps_current, meter.system_cps_current - meter.cache_hits_current);
            m2_set_hangupcause(cd, 342);
            meter.hgc342_dropped_calls++;
            return 1;

        }


    }

    return 0;

}


/*
    Used to find cd by uniqueid for EACH packet comming from Freeswitch servers

    Used in m2_radius_accounting [rlm_m2.c]
*/

static calldata_t *m2_get_session_by_uniqueid(char *uniqueid) {

    //calldata_t *cd = NULL, *node = NULL;

    // empty hash?
    if (cd_hash == NULL) return NULL;

    meter.getsession_count_start++;
    double start_time = m2_get_current_time();
    double run_time;

    // get cd from cd hash by uniqueid
    cd_hash_t *cdh = NULL;

    pthread_rwlock_rdlock(&cd_hash_lock);  // read lock to allow several threads to read from the hash at the same time
    HASH_FIND_STR(cd_hash, uniqueid, cdh);
    pthread_rwlock_unlock(&cd_hash_lock);

    if (cdh != NULL && cdh->cd != NULL && cdh->cd->call_state > M2_PROCESSING_STATE) {
        //m2_log(M2_DEBUG, "CD HASH: Found cd in hash by uniqueid [%s]\n", uniqueid);

        // saving metering stats
        run_time = m2_get_current_time() - start_time;
        meter.getsession_time += run_time;
        meter.getsession_count++;
        if (run_time > meter.getsession_time_max) meter.getsession_time_max = run_time;
        if (run_time > meter.getsession_time_maxps) meter.getsession_time_maxps = run_time;

        return cdh->cd;
    }

    // saving metering stats
    run_time = m2_get_current_time() - start_time;
    meter.getsession_time += run_time;
    meter.getsession_count++;
    if (run_time > meter.getsession_time_max) meter.getsession_time_max = run_time;
    if (run_time > meter.getsession_time_maxps) meter.getsession_time_maxps = run_time;

    return NULL;

}

static double m2_get_time(char *time_str) {

    double time_val = 0;
    char tmp_time_buffer1[20] = "";
    char tmp_time_buffer2[20] = "";

    if (strlen(time_str)) {
        strncpy(tmp_time_buffer1, time_str, 19);
        strncpy(tmp_time_buffer2, time_str + 20, 6);
        struct tm tm;
        time_t seconds;
        memset(&tm, 0, sizeof(struct tm));
        strptime(tmp_time_buffer1, M2_RADIUS_TIME_FORMAT, &tm);
        seconds = mktime(&tm);
        time_val = seconds + (atoi(tmp_time_buffer2)/1000000.0);
    }

    return time_val;
}


/*
    Mark answered call
*/


static void m2_answer_mark(calldata_t *cd) {

    char answer_time_str[64] = "";

    if (cd && cd->call_state < M2_ANSWERED_STATE) {

        // get answer time
        time_t raw_time;
        struct tm *tmm = NULL;

        raw_time = time(NULL);
        tmm = localtime(&raw_time);
        strftime(answer_time_str, sizeof(answer_time_str), DATETIME_FORMAT, tmm);

        if (strcmp(answer_time_str, "0000-00-00 00:00:00") == 0) {
            strlcpy(cd->answer_time_str, "NULL", sizeof(cd->answer_time_str));
        } else {
            sprintf(cd->answer_time_str, "'%s'", answer_time_str);
        }

        struct timeb tp;
        ftime(&tp);
        cd->answer_time = tp.time + (tp.millitm / 1000.0);

        cd->call_state = M2_ANSWERED_STATE;
        m2_log(M2_DEBUG, "Changed call state to: %s\n", call_state_str[M2_ANSWERED_STATE] == NULL ? "UNKNOWN" : call_state_str[M2_ANSWERED_STATE]);
        // set flag that this call should be updated
        cd->active_call_update = 1;

    }

}


/*
    Terminate radius
*/

static void *m2_terminate_radius() {

    int timeout = 5;
    int count = 0;
    calldata_t *cd = NULL;

    if (active_calls_check_timer_period > 0) {
        timeout = active_calls_check_timer_period + 5;
    }

    while (count < timeout) {
        sleep(1);
        m2_log(M2_WARNING, "Radius will shutdown in %d\n", timeout - count);
        count++;
    }

    exit(0);
    pthread_exit(NULL);

}

static void *m2_delayed_terminate_radius() {

    sleep(global_call_timeout);
    exit(0);
    pthread_exit(NULL);

}

static void m2_init_terminate_radius() {

    pthread_t thread_id;
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_create(&thread_id, &thread_attr, m2_terminate_radius, NULL);
    pthread_create(&thread_id, &thread_attr, m2_delayed_terminate_radius, NULL);
    pthread_attr_destroy(&thread_attr);

}


/*
    Check if destination number is in blacklist/whitelist
*/


static int m2_check_static_blacklist(calldata_t *cd, int list_id, char *enable_static_list, char *number) {

    MYSQL_RES *result;
    MYSQL_ROW row;
    int connection = 0;
    char sqlcmd[2048] = "";
    char number_from_db[256] = "";

    int found = 0;

    // get number from blacklist/whitelist
    if (!strlen(number) || strcmp(number, "nobody") == 0) {
        sprintf(sqlcmd, "SELECT number FROM numbers WHERE number = 'empty' AND number_pool_id = %d LIMIT 1", list_id);
    } else {
        sprintf(sqlcmd, "SELECT number FROM numbers WHERE '%s' LIKE number AND number_pool_id = %d LIMIT 1", number, list_id);
    }

    if (m2_mysql_query(cd, sqlcmd, &connection)) {
        return 0;
    }

    // query succeeded, get results and mark connection as available
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

    if (found && strcmp(enable_static_list, "blacklist") == 0) {
        if (strchr(number_from_db, '%')) {
            m2_log(M2_WARNING, "Number '%s' matches prefix '%s' in static blacklist! (number_pool_id: %d)\n", number, number_from_db, list_id);
        } else {
            m2_log(M2_WARNING, "Number '%s' is in static blacklist! (number_pool_id: %d)\n", number, list_id);
        }
        return 1;
    }

    if (!found && strcmp(enable_static_list, "whitelist") == 0) {
        m2_log(M2_WARNING, "Number '%s' is not in static whitelist! (number_pool_id: %d)\n", number, list_id);
        return -1;
    }

    return 0;

}


/*
    Save call tracing from file to DB
*/


static void m2_save_call_tracing(char *uniqueid) {

    FILE *fp = NULL;
    char filename[256] = "";
    char line[1024] = "";
    char log_file_data[65536] = "";
    char sqlcmd[65536] = "";
    int found = 0;
    int connection = 0;
    int i = 0;

    sprintf(filename, "/tmp/m2/m2_call_tracing/%s.m2_call_trace", uniqueid);

    fp = fopen(filename, "r");

    if (fp) {
        while (!feof(fp)) {
            strcpy(line, "");
            fgets(line, 1024, fp);

            // clean strings
            if (strlen(line)) {
                for (i = 0; i < strlen(line); i++) {
                    if (line[i] == '"') {
                        line[i] = '`';
                    }
                }
            }

            strcat(log_file_data, line);
            found = 1;
        }
        fclose(fp);
    } else {
        calldata_t *cd = NULL;
        m2_log(M2_ERROR, "Call trace file %s not found\n", filename);
    }

    if (found) {

        // firstly delete old log
        sprintf(sqlcmd, "DELETE FROM call_logs WHERE uniqueid = '%s'", uniqueid);
        if (m2_mysql_query(NULL, sqlcmd, &connection)) {
            return;
        }
        // mark connection as available
        mysql_connections[connection] = 0;

        // now insert new log
        sprintf(sqlcmd, "INSERT INTO call_logs (uniqueid, log) VALUES ('%s', \"%s\")", uniqueid, log_file_data);
        if (m2_mysql_query(NULL, sqlcmd, &connection)) {
            return;
        }
        // mark connection as available
        mysql_connections[connection] = 0;
    }

    remove(filename);

}


/*
 * Extracts a number part from a specified uri scheme
 * Checking order is >,@,; so that number would be correctly extracted from strings like:
 * <uri_scheme:number;header@IPorDomain>
 * <uri_scheme:number@IPorDomain>
 * <uri_scheme:number;header>
 * <uri_scheme:number>

 * return 1 if number part is parsed, 0 otherwise
*/


static void m2_parse_header_number_part(char *header, char *number, int number_len) {

    const char *uris[] = {"sip:", "sips:", "tel:"};
    int size = sizeof(uris) / sizeof(uris[0]);
    int i = 0;
    int len = strlen(header);

    if (len > (number_len - 1)) {
        len = number_len - 1;
    }

    for (i = 0; i < size; i++) {
        char *uri_start_pos = strstr(header, uris[i]);

        if (uri_start_pos) {
            char *number_end_pos1 = strchr(uri_start_pos, '>');

            if (number_end_pos1) {
                *number_end_pos1 = '\0';
            }

            char *number_end_pos2 = strchr(uri_start_pos, '@');

            if (number_end_pos2) {
                *number_end_pos2 = '\0';
            }

            char *number_end_pos3 = strchr(uri_start_pos, ';');

            if (number_end_pos3) {
                *number_end_pos3 = '\0';
            }

            strncpy(number, uri_start_pos + strlen(uris[i]), len);
            return;
        }
    }

    // handle cases like:
    // P-Asserted-Identity: +370123456789
    // P-Asserted-Identity: 370123456789
    char *digit_start_pos = header;

    while (!isdigit(*digit_start_pos) && *digit_start_pos != '+' && *digit_start_pos != '\0') digit_start_pos++;

    if (*digit_start_pos != '\0') {
        char *digit_end_pos = digit_start_pos;

        if (*digit_start_pos == '+') {
            digit_end_pos++;
        }

        while (digit_end_pos && isdigit(*digit_end_pos)) digit_end_pos++;
        *digit_end_pos = '\0';

        strncpy(number, digit_start_pos, len);
        return;
    }

    // When no sip/sips/tel uri is found tries to extract identity data in ""
    char *str_start_pos = strchr(header, '"');

    if (str_start_pos) {
        char *str_end_pos = strchr(str_start_pos + 1, '"');

        if (str_end_pos) {
            *str_end_pos = '\0';
            strncpy(number, str_start_pos + 1, len);
            return;
        }
    }
}



/*
    Get current time in unixtime seconds
*/

static unsigned long int m2_unixtime() {

    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;

}

/*
    Get current time + miliseconds
*/


static double m2_get_current_time() {
    struct timeval t;
    struct timezone tzp;
    gettimeofday(&t, &tzp);
    return t.tv_sec + t.tv_usec*1e-6;
}


/*
    Get freeswitch server IP by ID
*/


static void m2_get_freeswitch_server_ip(int server_id, char *server_ip, int server_ip_len) {

    int i = 0;
    int found = 0;

    for (i = 0; i < freeswitch_servers_count; i++) {
        if (freeswitch_servers[i].id == server_id) {
            strlcpy(server_ip, freeswitch_servers[i].ip, server_ip_len);
            found = 1;
        }
    }

    if (!found) {
        strlcpy(server_ip, "127.0.0.1", server_ip_len);
    }
}


/*
    Remove special characters (' \) in strings
*/


static void m2_filter_string(char *string) {

    char *r, *w;

    for (w = r = string; *r; r++) {
        if (*r != '\'' && *r != '\\') {
            *w++ = *r;
        }
    }

    *w = '\0';

}


/*
    Allow only # * + 0-9 A-Z a-z in strings
    http://www.asciitable.com/
    https://theasciicode.com.ar/
*/


static void m2_filter_string_strict(char *string) {

    char *r, *w;

    for (w = r = string; *r; r++) {
        if (*r == 35 || *r == 42 || *r == 43 || (*r > 47 && *r < 58) || (*r > 64 && *r < 91) || (*r > 96 && *r < 123)) {
            *w++ = *r;
        }
    }

    *w = '\0';

}


/*
    Check regexp
    0 - match
    1 - no match
    2 - error
    https://stackoverflow.com/questions/1085083/regular-expressions-in-c-examples
*/


static int m2_regexp(char *string, char *regexp_str) {

    calldata_t *cd = NULL;
    int res = 0;

#ifdef FREERADIUS3

    pcre *re;
    const char *error;
    int erroffset;
    int rc;

    re = pcre_compile(
        regexp_str,             /* the pattern */
        0,                      /* default options */
        &error,                 /* for error message */
        &erroffset,             /* for error offset */
        NULL                    /* use default character tables */
    );

    if (re == NULL) {
        m2_log(M2_ERROR, "Pattern (%s) compilation failed: %s\n", regexp_str, error);
        return 2;
    }

    rc = pcre_exec(
        re,                     /* the compiled pattern */
        NULL,                   /* no extra data - we didn't study the pattern */
        string,                 /* the subject string */
        strlen(string),         /* the length of the subject */
        0,                      /* start at offset 0 in the subject */
        0,                      /* default options */
        NULL,                   /* output vector for substring information */
        0                       /* number of elements in the output vector */
    );

    /* Matching failed: handle error cases */
    if (rc < 0) {
        switch(rc) {
            case PCRE_ERROR_NOMATCH:
                res = 1;
                break;
            default:
                res = 2;
                break;
        }
    } else {
        res = 0;
    }

    /* Release memory used for the compiled pattern */
    pcre_free(re);

#else

    int reti = 0;
    regex_t regex;

    reti = regcomp(&regex, regexp_str, REG_EXTENDED);

    if (reti) {
        m2_log(M2_WARNING, "Could not compile regex: %s for string: %s\n", regexp_str, string);
        return 2;
    }

    reti = regexec(&regex, string, 0, NULL, 0);

    if (!reti) {
        res = 0;
    } else if (reti == REG_NOMATCH) {
        res = 1;
    } else {
        m2_log(M2_WARNING, "Regex match failed regex: %s\n", regexp_str);
        return 2;
    }

    regfree(&regex);

#endif

    return res;
}




static void m2_cd_free_memory(calldata_t **cd_ptr) {

    calldata_t *cd = NULL;


        // free termination points and dial peers
        m2_free_tp_dp((*cd_ptr)->dpeers, (*cd_ptr)->dpeers_count);
        m2_free_tp_dp((*cd_ptr)->failover_1_dpeers, (*cd_ptr)->failover_1_dpeers_count);
        m2_free_tp_dp((*cd_ptr)->failover_2_dpeers, (*cd_ptr)->failover_2_dpeers_count);

        if ((*cd_ptr)->dpeers) {
            free((*cd_ptr)->dpeers);
            (*cd_ptr)->dpeers = NULL;
        }

        if ((*cd_ptr)->failover_1_dpeers) {
            free((*cd_ptr)->failover_1_dpeers);
            (*cd_ptr)->failover_1_dpeers = NULL;
        }

        if ((*cd_ptr)->failover_2_dpeers) {
            free((*cd_ptr)->failover_2_dpeers);
            (*cd_ptr)->failover_2_dpeers = NULL;
        }

        // free routing table
        if ((*cd_ptr)->routing_table) {
            free((*cd_ptr)->routing_table);
            (*cd_ptr)->routing_table = NULL;
        }

        // free op
        if ((*cd_ptr)->op) {
            free((*cd_ptr)->op);
            (*cd_ptr)->op = NULL;
        }

        // free tmp_dps
        if ((*cd_ptr)->tmp_dps) {
            free((*cd_ptr)->tmp_dps);
            (*cd_ptr)->tmp_dps = NULL;
        }

        // free calldata
        if (*cd_ptr) {

            m2_log(M2_DEBUG, "Freeing cd %s\n", (*cd_ptr)->uniqueid);

            free(*cd_ptr);
            *cd_ptr = NULL;

            meter.freed_calls_total++;

        }

}


/*
     Checking if we can lock the mutex - if no it means mutex is locked
     returns 1 if mutex is locked
     returns 0 if mutex is unlocked
*/


int m2_check_mutex(pthread_mutex_t *mutex){

    int res = 0;

    if (pthread_mutex_trylock(mutex) != 0) {
        res = 1;
    } else {
        pthread_mutex_unlock(mutex);
    }

    return res;
}
