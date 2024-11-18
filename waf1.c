#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_array_t *ip_blacklist;      
    ngx_array_t *ip_whitelist;      
    ngx_array_t *url_whitelist;     
    ngx_array_t *reject_urls;       
    ngx_array_t *reject_keywords;   
    ngx_array_t *user_agent_rules;  
    ngx_array_t *cookie_rules;      
    ngx_str_t error_log_path;       // 新增日志文件路径成员
} ngx_http_reject_rule_loc_conf_t;

static void *ngx_http_reject_rule_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_reject_rule_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_load_reject_rules(ngx_conf_t *cf, ngx_array_t **rules, ngx_str_t *filename);

static char *ngx_http_reject_ip_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_ip_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_url_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_keyword(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_user_agent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_reject_cookie(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_log_reject(ngx_http_request_t *r, const char *reason, ngx_http_reject_rule_loc_conf_t *rlcf);

static ngx_int_t ngx_http_reject_rule_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_reject_rule_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_reject_rule_module_ctx = {
    NULL,                                  // preconfiguration
    ngx_http_reject_rule_init,             // postconfiguration
    NULL,                                  // create main configuration
    NULL,                                  // init main configuration
    NULL,                                  // create server configuration
    NULL,                                  // merge server configuration
    ngx_http_reject_rule_create_loc_conf,  // create location configuration
    ngx_http_reject_rule_merge_loc_conf    // merge location configuration
};

static ngx_command_t ngx_http_reject_rule_commands[] = {
    {
        ngx_string("ip_blacklist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_ip_blacklist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("ip_whitelist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_ip_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("url_whitelist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_url_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("reject_url"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_url,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("reject_keyword"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_keyword,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("reject_user_agent"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_user_agent,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("reject_cookie"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_reject_cookie,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("warn_log"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_reject_rule_loc_conf_t, error_log_path),
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_http_reject_rule_module = {
    NGX_MODULE_V1,
    &ngx_http_reject_rule_module_ctx,      // module context
    ngx_http_reject_rule_commands,         // module directives
    NGX_HTTP_MODULE,                       // module type
    NULL,                                  // init master
    NULL,                                  // init module
    NULL,                                  // init process
    NULL,                                  // init thread
    NULL,                                  // exit thread
    NULL,                                  // exit process
    NULL,                                  // exit master
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_reject_rule_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_reject_rule_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_reject_rule_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->ip_blacklist = NGX_CONF_UNSET_PTR;
    conf->ip_whitelist = NGX_CONF_UNSET_PTR;
    conf->url_whitelist = NGX_CONF_UNSET_PTR;
    conf->reject_urls = NGX_CONF_UNSET_PTR;
    conf->reject_keywords = NGX_CONF_UNSET_PTR;
    conf->user_agent_rules = NGX_CONF_UNSET_PTR;
    conf->cookie_rules = NGX_CONF_UNSET_PTR;
    conf->error_log_path.len = 0;
    conf->error_log_path.data = NULL;
    return conf; 
}

static char *ngx_http_reject_rule_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_reject_rule_loc_conf_t *prev = parent;
    ngx_http_reject_rule_loc_conf_t *conf = child;

    if (conf->ip_blacklist == NGX_CONF_UNSET_PTR) {
        conf->ip_blacklist = prev->ip_blacklist;
    }
    if (conf->ip_whitelist == NGX_CONF_UNSET_PTR) {
        conf->ip_whitelist = prev->ip_whitelist;
    }
    if (conf->url_whitelist == NGX_CONF_UNSET_PTR) {
        conf->url_whitelist = prev->url_whitelist;
    }
    if (conf->reject_urls == NGX_CONF_UNSET_PTR) {
        conf->reject_urls = prev->reject_urls;
    }
    if (conf->reject_keywords == NGX_CONF_UNSET_PTR) {
        conf->reject_keywords = prev->reject_keywords;
    }
    if (conf->user_agent_rules == NGX_CONF_UNSET_PTR) {
        conf->user_agent_rules = prev->user_agent_rules;
    }
    if (conf->cookie_rules == NGX_CONF_UNSET_PTR) {
        conf->cookie_rules = prev->cookie_rules;
    }
    if (conf->error_log_path.len == 0) {
        conf->error_log_path = prev->error_log_path;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_load_reject_rules(ngx_conf_t *cf, ngx_array_t **rules, ngx_str_t *filename) {
    ngx_file_t file;
    ngx_file_info_t fi;
    ngx_str_t *rule;
    u_char *buf, *p, *end;

    file.name = *filename;
    file.log = cf->log;

    if (ngx_file_info(filename->data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno, ngx_file_info_n " \"%s\" failed", filename->data);
        return NGX_ERROR;
    }

    file.fd = ngx_open_file(filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno, ngx_open_file_n " \"%s\" failed", filename->data);
        return NGX_ERROR;
    }

    buf = ngx_palloc(cf->pool, ngx_file_size(&fi));
    if (buf == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    if (ngx_read_file(&file, buf, ngx_file_size(&fi), 0) == NGX_ERROR) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    ngx_close_file(file.fd);

    p = buf;
    end = buf + ngx_file_size(&fi);

    while (p < end) {
        while (p < end && (*p == '\n' || *p == '\r')) {
            p++;
        }

        if (p == end) {
            break;
        }

        u_char *start = p;

        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }

        if (*rules == NGX_CONF_UNSET_PTR) {
            *rules = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
            if (*rules == NULL) {
return NGX_ERROR;
}
}

    rule = ngx_array_push(*rules);
    if (rule == NULL) {
        return NGX_ERROR;
    }

    rule->data = ngx_pnalloc(cf->pool, p - start + 1);
    if (rule->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(rule->data, start, p - start);
    rule->data[p - start] = '\0';  // ??nullβ
    rule->len = p - start;
}

return NGX_OK;
}

static char *ngx_http_reject_ip_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->ip_blacklist, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_ip_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->ip_whitelist, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_url_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->url_whitelist, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->reject_urls, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_keyword(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->reject_keywords, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_user_agent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->user_agent_rules, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *ngx_http_reject_cookie(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
ngx_http_reject_rule_loc_conf_t *rlcf = conf;
ngx_str_t *value = cf->args->elts;

return ngx_http_load_reject_rules(cf, &rlcf->cookie_rules, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static void ngx_http_log_reject(ngx_http_request_t *r, const char *reason, ngx_http_reject_rule_loc_conf_t *rlcf) {
    ngx_log_t *log;
    ngx_fd_t fd;

    log = ngx_pcalloc(r->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return;
    }

    log->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (log->file == NULL) {
        return;
    }

    fd = ngx_open_file(rlcf->error_log_path.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to open error log file: %s", rlcf->error_log_path.data);
        return;
    }

    log->file->fd = fd;
    log->log_level = NGX_LOG_ERR;
    log->action = NULL;
    log->data = r->pool;
    log->handler = NULL;
    log->next = NULL;

    ngx_log_error(NGX_LOG_ERR, log, 0, "Request rejected: %s, IP: %V, Port: %d, URI: %V, User-Agent: %V",
                  reason, &r->connection->addr_text, ntohs(r->connection->sockaddr->sa_family == AF_INET ?
                  ((struct sockaddr_in *) r->connection->sockaddr)->sin_port : ((struct sockaddr_in6 *) r->connection->sockaddr)->sin6_port), &r->uri, &r->headers_in.user_agent->value);

    ngx_close_file(fd);
}

static ngx_int_t ngx_http_reject_rule_handler(ngx_http_request_t *r) {
    ngx_http_reject_rule_loc_conf_t *rlcf;
    ngx_uint_t i;
    ngx_str_t uri, args;
    u_char *p, *last;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_reject_rule_module);

    p = r->uri.data;
    last = p + r->uri.len;

    // 初始化 uri 和 args
    uri.len = 0;
    uri.data = NULL;
    args.len = 0;
    args.data = NULL;

    // Split URI into path and query arguments
    u_char *query_start = (u_char *)ngx_strchr(r->uri.data, '?');
    if (query_start != NULL) {
        uri.len = query_start - p;
        uri.data = p;
        args.len = last - query_start - 1;
        args.data = (u_char *)query_start + 1;
    } else {
        uri = r->uri;
    }

    // IP Blacklist
    if (rlcf->ip_blacklist != NGX_CONF_UNSET_PTR) {
        ngx_str_t *ips = rlcf->ip_blacklist->elts;
        for (i = 0; i < rlcf->ip_blacklist->nelts; i++) {
            if (ngx_strncmp(r->connection->addr_text.data, ips[i].data, ips[i].len) == 0) {
                ngx_http_log_reject(r, "IP Blacklist", rlcf);
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    // IP Whitelist
    if (rlcf->ip_whitelist != NGX_CONF_UNSET_PTR) {
        ngx_str_t *ips = rlcf->ip_whitelist->elts;
        ngx_uint_t allowed = 0;
        for (i = 0; i < rlcf->ip_whitelist->nelts; i++) {
            if (ngx_strncmp(r->connection->addr_text.data, ips[i].data, ips[i].len) == 0) {
                allowed = 1;
                break;
            }
        }
        if (!allowed) {
            ngx_http_log_reject(r, "IP Not in Whitelist", rlcf);
            return NGX_HTTP_FORBIDDEN;
        }
    }

    // URL whitelist check
    if (rlcf->url_whitelist != NGX_CONF_UNSET_PTR) {
        ngx_str_t *urls = rlcf->url_whitelist->elts;
        for (i = 0; i < rlcf->url_whitelist->nelts; i++) {
            if (ngx_strncmp(uri.data, urls[i].data,urls[i].len) == 0) {
                return NGX_DECLINED; // URL is in whitelist, decline further processing
            }
        }
    }

    // URL blacklist check
    if (rlcf->reject_urls != NGX_CONF_UNSET_PTR) {
        ngx_str_t *urls = rlcf->reject_urls->elts;
        for (i = 0; i < rlcf->reject_urls->nelts; i++) {
            if (ngx_strncmp(uri.data, urls[i].data,urls[i].len) == 0) {
                ngx_http_log_reject(r, "URL Rejected", rlcf);
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    // Check GET request query parameters for keywords
    if (args.len > 0 && rlcf->reject_keywords != NGX_CONF_UNSET_PTR) {
        ngx_str_t *keywords = rlcf->reject_keywords->elts;
        for (i = 0; i < rlcf->reject_keywords->nelts; i++) {
            if (ngx_strstr(args.data, keywords[i].data) != NULL) {
                ngx_http_log_reject(r, "Keyword in Query Args Rejected", rlcf);
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    // Check POST request body for keywords
    if (r->method == NGX_HTTP_POST && r->request_body && rlcf->reject_keywords != NGX_CONF_UNSET_PTR) {
        ngx_chain_t *cl;
        ngx_buf_t *buf;
        ngx_str_t content;
        ngx_str_t *keywords = rlcf->reject_keywords->elts;

        cl = r->request_body->bufs;
        while (cl) {
            buf = cl->buf;
            if (buf->pos < buf->last) { // Ensure buf has data
                content.data = buf->pos;
                content.len = buf->last - buf->pos;
                for (i = 0; i < rlcf->reject_keywords->nelts; i++) {
                    if (ngx_strstr(content.data, keywords[i].data) != NULL) {
                        ngx_http_log_reject(r, "Keyword in POST Body Rejected", rlcf);
                        return NGX_HTTP_FORBIDDEN;
                    }
                }
            }
            cl = cl->next;
        }
    }

    // User-Agent
    if (rlcf->user_agent_rules != NGX_CONF_UNSET_PTR) {
        ngx_str_t *rules = rlcf->user_agent_rules->elts;
        for (i = 0; i < rlcf->user_agent_rules->nelts; i++) {
            if (r->headers_in.user_agent != NULL &&
                ngx_strstr(r->headers_in.user_agent->value.data, (char *)rules[i].data) != NULL) {
                ngx_http_log_reject(r, "User-Agent Rejected", rlcf);
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    // Cookie
    if (rlcf->cookie_rules != NGX_CONF_UNSET_PTR) {
        ngx_str_t *rules = rlcf->cookie_rules->elts;
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *header = part->elts;
        for (i = 0; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                header = part->elts;
                i = 0;
            }
            if (ngx_strncmp(header[i].key.data, "Cookie", header[i].key.len) == 0) {
                ngx_uint_t j;
                for (j = 0; j < rlcf->cookie_rules->nelts; j++) {
                    if (ngx_strstr(header[i].value.data, (char *)rules[j].data) != NULL) {
                        ngx_http_log_reject(r, "Cookie Rejected", rlcf);
                        return NGX_HTTP_FORBIDDEN;
                    }
                }
            }
        }
    }

    // 如果所有检查都通过，则返回 NGX_DECLINED，继续处理请求
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_reject_rule_init(ngx_conf_t *cf) {
ngx_http_handler_pt        *h;
ngx_http_core_main_conf_t  *cmcf;

cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
if (h == NULL) {
    return NGX_ERROR;
}

*h = ngx_http_reject_rule_handler;

return NGX_OK;
}

