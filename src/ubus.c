/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#ifdef HAVE_UBUS

#include <libubus.h>

static struct blob_buf b;
static int error_logged = 0;

static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg);

#ifdef HAVE_DHCP
enum {
  ADD_LEASE_IP,
  ADD_LEASE_MAC,
  ADD_LEASE_HOSTNAME,
  ADD_LEASE_CLIENT_ID,
  ADD_LEASE_EXPIRES,
  ADD_LEASE_IA_ID,
  ADD_LEASE_IS_TEMPORARY,
  __ADD_LEASE_MAX
};

static const struct blobmsg_policy add_lease_policy[__ADD_LEASE_MAX] = {
  [ADD_LEASE_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
  [ADD_LEASE_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
  [ADD_LEASE_HOSTNAME] = { .name = "hostname", .type = BLOBMSG_TYPE_STRING },
  [ADD_LEASE_CLIENT_ID] = { .name = "client_id", .type = BLOBMSG_TYPE_STRING },
  [ADD_LEASE_EXPIRES] = { .name = "expires", .type = BLOBMSG_TYPE_INT32 },
  [ADD_LEASE_IA_ID] = { .name = "iaid", .type = BLOBMSG_TYPE_INT32 },
  [ADD_LEASE_IS_TEMPORARY] = { .name = "is_temporary", .type = BLOBMSG_TYPE_BOOL },
};

enum {
  DELETE_LEASE_IP,
  __DELETE_LEASE_MAX
};

static const struct blobmsg_policy delete_lease_policy[__DELETE_LEASE_MAX] = {
  [DELETE_LEASE_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_handle_add_lease(struct ubus_context *ctx, struct ubus_object *obj,
				  struct ubus_request_data *req, const char *method,
				  struct blob_attr *msg);
static int ubus_handle_delete_lease(struct ubus_context *ctx, struct ubus_object *obj,
				     struct ubus_request_data *req, const char *method,
				     struct blob_attr *msg);
static int ubus_handle_get_leases(struct ubus_context *ctx, struct ubus_object *obj,
				   struct ubus_request_data *req, const char *method,
				   struct blob_attr *msg);
#endif

#ifdef HAVE_CONNTRACK
enum {
  SET_CONNMARK_ALLOWLIST_MARK,
  SET_CONNMARK_ALLOWLIST_MASK,
  SET_CONNMARK_ALLOWLIST_PATTERNS
};
static const struct blobmsg_policy set_connmark_allowlist_policy[] = {
  [SET_CONNMARK_ALLOWLIST_MARK] = {
    .name = "mark",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_MASK] = {
    .name = "mask",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_PATTERNS] = {
    .name = "patterns",
    .type = BLOBMSG_TYPE_ARRAY
  }
};
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg);
#endif

static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj);

static const struct ubus_method ubus_object_methods[] = {
  UBUS_METHOD_NOARG("metrics", ubus_handle_metrics),
#ifdef HAVE_DHCP
  UBUS_METHOD("add_lease", ubus_handle_add_lease, add_lease_policy),
  UBUS_METHOD("delete_lease", ubus_handle_delete_lease, delete_lease_policy),
  UBUS_METHOD_NOARG("get_leases", ubus_handle_get_leases),
#endif
#ifdef HAVE_CONNTRACK
  UBUS_METHOD("set_connmark_allowlist", ubus_handle_set_connmark_allowlist, set_connmark_allowlist_policy),
#endif
};

static struct ubus_object_type ubus_object_type =
  UBUS_OBJECT_TYPE("dnsmasq", ubus_object_methods);

static struct ubus_object ubus_object = {
  .name = NULL,
  .type = &ubus_object_type,
  .methods = ubus_object_methods,
  .n_methods = ARRAY_SIZE(ubus_object_methods),
  .subscribe_cb = ubus_subscribe_cb,
};

static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
  (void)ctx;

  my_syslog(LOG_DEBUG, _("UBus subscription callback: %s subscriber(s)"), obj->has_subscribers ? "1" : "0");
}

static void ubus_destroy(struct ubus_context *ubus)
{
  ubus_free(ubus);
  daemon->ubus = NULL;
  
  /* Forces re-initialization when we're reusing the same definitions later on. */
  ubus_object.id = 0;
  ubus_object_type.id = 0;
}

static void ubus_disconnect_cb(struct ubus_context *ubus)
{
  int ret;

  ret = ubus_reconnect(ubus, NULL);
  if (ret)
    {
      my_syslog(LOG_ERR, _("Cannot reconnect to UBus: %s"), ubus_strerror(ret));

      ubus_destroy(ubus);
    }
}

char *ubus_init()
{
  struct ubus_context *ubus = NULL;
  int ret = 0;

  if (!(ubus = ubus_connect(NULL)))
    return NULL;
  
  ubus_object.name = daemon->ubus_name;
  ret = ubus_add_object(ubus, &ubus_object);
  if (ret)
    {
      ubus_destroy(ubus);
      return (char *)ubus_strerror(ret);
    }    
  
  ubus->connection_lost = ubus_disconnect_cb;
  daemon->ubus = ubus;
  error_logged = 0;

  return NULL;
}

void set_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot set UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }

  error_logged = 0;

  poll_listen(ubus->sock.fd, POLLIN);
  poll_listen(ubus->sock.fd, POLLERR);
  poll_listen(ubus->sock.fd, POLLHUP);
}

void check_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot poll UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }
  
  error_logged = 0;

  if (poll_check(ubus->sock.fd, POLLIN))
    ubus_handle_event(ubus);
  
  if (poll_check(ubus->sock.fd, POLLHUP | POLLERR))
    {
      my_syslog(LOG_INFO, _("Disconnecting from UBus"));

      ubus_destroy(ubus);
    }
}

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return (UBUS_STATUS_UNKNOWN_ERROR); \
      } \
  } while (0)

static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg)
{
  int i;

  (void)obj;
  (void)method;
  (void)msg;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));

  for (i=0; i < __METRIC_MAX; i++)
    CHECK(blobmsg_add_u32(&b, get_metric_name(i), daemon->metrics[i]));

  CHECK(ubus_send_reply(ctx, req, b.head));
  return UBUS_STATUS_OK;
}

#ifdef HAVE_DHCP
static int ubus_handle_add_lease(struct ubus_context *ctx, struct ubus_object *obj,
				  struct ubus_request_data *req, const char *method,
				  struct blob_attr *msg)
{
  struct blob_attr *tb[__ADD_LEASE_MAX];
  struct dhcp_lease *lease;
  const char *ipaddr, *hwaddr, *hostname, *client_id;
  union all_addr addr;
  unsigned char hwaddr_bin[DHCP_CHADDR_MAX];
  unsigned char clid_bin[256];
  int hw_len, hw_type, clid_len = 0;
  time_t now = dnsmasq_time();
  uint32_t expires;
  uint32_t ia_id = 0;
  int is_temporary = 0;

  (void)ctx;
  (void)obj;
  (void)req;
  (void)method;

  blobmsg_parse(add_lease_policy, __ADD_LEASE_MAX, tb, blob_data(msg), blob_len(msg));

  if (!tb[ADD_LEASE_IP] || !tb[ADD_LEASE_MAC] || !tb[ADD_LEASE_EXPIRES])
    {
      my_syslog(LOG_ERR, _("UBus add_lease: missing required parameters (ip, mac, expires)"));
      return UBUS_STATUS_INVALID_ARGUMENT;
    }

  ipaddr = blobmsg_get_string(tb[ADD_LEASE_IP]);
  hwaddr = blobmsg_get_string(tb[ADD_LEASE_MAC]);
  expires = blobmsg_get_u32(tb[ADD_LEASE_EXPIRES]);

  hostname = tb[ADD_LEASE_HOSTNAME] ? blobmsg_get_string(tb[ADD_LEASE_HOSTNAME]) : NULL;
  client_id = tb[ADD_LEASE_CLIENT_ID] ? blobmsg_get_string(tb[ADD_LEASE_CLIENT_ID]) : NULL;

  if (tb[ADD_LEASE_IA_ID])
    ia_id = blobmsg_get_u32(tb[ADD_LEASE_IA_ID]);

  if (tb[ADD_LEASE_IS_TEMPORARY])
    is_temporary = blobmsg_get_bool(tb[ADD_LEASE_IS_TEMPORARY]);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    {
      if (!daemon->dhcp)
	{
	  my_syslog(LOG_ERR, _("UBus add_lease: DHCPv4 not configured"));
	  return UBUS_STATUS_INVALID_ARGUMENT;
	}

      if (ia_id != 0 || is_temporary)
	{
	  my_syslog(LOG_ERR, _("UBus add_lease: iaid and is_temporary must be zero for IPv4"));
	  return UBUS_STATUS_INVALID_ARGUMENT;
	}

      if (!(lease = lease_find_by_addr(addr.addr4)))
	lease = lease4_allocate(addr.addr4);
    }
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    {
      if (!daemon->doing_dhcp6)
	{
	  my_syslog(LOG_ERR, _("UBus add_lease: DHCPv6 not configured"));
	  return UBUS_STATUS_INVALID_ARGUMENT;
	}

      if (!(lease = lease6_find_by_addr(&addr.addr6, 128, 0)))
	lease = lease6_allocate(&addr.addr6, is_temporary ? LEASE_TA : LEASE_NA);

      if (lease)
	lease_set_iaid(lease, ia_id);
    }
#endif
  else
    {
      my_syslog(LOG_ERR, _("UBus add_lease: invalid IP address '%s'"), ipaddr);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }

  if (!lease)
    {
      my_syslog(LOG_ERR, _("UBus add_lease: unable to allocate lease for %s"), ipaddr);
      return UBUS_STATUS_UNKNOWN_ERROR;
    }

  hw_len = parse_hex((char*)hwaddr, hwaddr_bin, DHCP_CHADDR_MAX, NULL, &hw_type);
  if (hw_len < 0)
    {
      my_syslog(LOG_ERR, _("UBus add_lease: invalid MAC address '%s'"), hwaddr);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }

  if (hw_type == 0 && hw_len != 0)
    hw_type = ARPHRD_ETHER;

  if (client_id && *client_id)
    {
      clid_len = parse_hex((char*)client_id, clid_bin, sizeof(clid_bin), NULL, NULL);
      if (clid_len < 0)
	{
	  my_syslog(LOG_WARNING, _("UBus add_lease: invalid client_id '%s', ignoring"), client_id);
	  clid_len = 0;
	}
    }

  lease_set_hwaddr(lease, hwaddr_bin, clid_len > 0 ? clid_bin : NULL,
		   hw_len, hw_type, clid_len, now, 0);

  /* expires is duration (seconds remaining), matching dbus AddDhcpLease convention */
  lease_set_expires(lease, expires, now);

  if (hostname && *hostname)
    {
      if (!legal_hostname((char *)hostname))
	{
	  my_syslog(LOG_ERR, _("UBus add_lease: invalid hostname '%s'"), hostname);
	  return UBUS_STATUS_INVALID_ARGUMENT;
	}

#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	lease_set_hostname(lease, hostname, 0, get_domain6(&lease->addr6), NULL);
      else
#endif
	lease_set_hostname(lease, hostname, 0, get_domain(lease->addr), NULL);
    }

  lease_update_file(now);
  lease_update_dns(0);

  /* Clear script-triggering flags - externally injected leases should not
     trigger dhcp-script, matching the behavior of read_leases() at startup.
     This prevents ping-pong in HA setups where lease-sync injects leases. */
  lease->flags &= ~(LEASE_NEW | LEASE_CHANGED | LEASE_AUX_CHANGED | LEASE_EXP_CHANGED);

  my_syslog(LOG_INFO, _("UBus add_lease: added %s %s %s"),
	    ipaddr, hwaddr, hostname ? hostname : "");

  return UBUS_STATUS_OK;
}

static int ubus_handle_delete_lease(struct ubus_context *ctx, struct ubus_object *obj,
				     struct ubus_request_data *req, const char *method,
				     struct blob_attr *msg)
{
  struct blob_attr *tb[__DELETE_LEASE_MAX];
  struct dhcp_lease *lease = NULL;
  const char *ipaddr;
  union all_addr addr;
  time_t now = dnsmasq_time();

  (void)ctx;
  (void)obj;
  (void)req;
  (void)method;

  blobmsg_parse(delete_lease_policy, __DELETE_LEASE_MAX, tb, blob_data(msg), blob_len(msg));

  if (!tb[DELETE_LEASE_IP])
    return UBUS_STATUS_INVALID_ARGUMENT;

  ipaddr = blobmsg_get_string(tb[DELETE_LEASE_IP]);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4) && daemon->dhcp)
    lease = lease_find_by_addr(addr.addr4);
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6) && daemon->doing_dhcp6)
    lease = lease6_find_by_addr(&addr.addr6, 128, 0);
#endif

  if (!lease)
    {
      my_syslog(LOG_DEBUG, _("UBus delete_lease: lease not found for %s"), ipaddr);
      return UBUS_STATUS_NOT_FOUND;
    }

  lease_prune(lease, now);
  lease_update_file(now);
  lease_update_dns(0);

  my_syslog(LOG_INFO, _("UBus delete_lease: deleted %s"), ipaddr);

  return UBUS_STATUS_OK;
}

static int ubus_handle_get_leases(struct ubus_context *ctx, struct ubus_object *obj,
				   struct ubus_request_data *req, const char *method,
				   struct blob_attr *msg)
{
  struct dhcp_lease *lease;
  void *array, *table;
  char addr_str[INET6_ADDRSTRLEN];
  char hwaddr_str[DHCP_CHADDR_MAX * 3];
  int i;
  time_t now = dnsmasq_time();

  (void)obj;
  (void)method;
  (void)msg;

  CHECK(blob_buf_init(&b, 0));
  array = blobmsg_open_array(&b, "leases");

  for (lease = lease_get_all(); lease; lease = lease->next)
    {
      table = blobmsg_open_table(&b, NULL);

#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	{
	  inet_ntop(AF_INET6, &lease->addr6, addr_str, sizeof(addr_str));
	  CHECK(blobmsg_add_string(&b, "ip", addr_str));
	  CHECK(blobmsg_add_string(&b, "type", (lease->flags & LEASE_TA) ? "temporary" : "normal"));
	  CHECK(blobmsg_add_u32(&b, "iaid", lease->iaid));
	}
      else
#endif
	{
	  inet_ntop(AF_INET, &lease->addr, addr_str, sizeof(addr_str));
	  CHECK(blobmsg_add_string(&b, "ip", addr_str));
	}

      if (lease->hwaddr_len > 0)
	{
	  for (i = 0; i < lease->hwaddr_len && i < DHCP_CHADDR_MAX; i++)
	    sprintf(hwaddr_str + i * 3, "%02x:", lease->hwaddr[i]);
	  hwaddr_str[lease->hwaddr_len * 3 - 1] = '\0';
	  CHECK(blobmsg_add_string(&b, "mac", hwaddr_str));
	}

      if (lease->hostname && *lease->hostname)
	CHECK(blobmsg_add_string(&b, "hostname", lease->hostname));

      /* Expiry as duration (seconds remaining), matching add_lease input
	 and the dbus AddDhcpLease convention.
	 lease->expires==0 means infinite; lease_set_expires uses 0xffffffff
	 as the infinite sentinel on input, so return that for round-trip. */
      if (lease->expires == 0)
	CHECK(blobmsg_add_u32(&b, "expires", 0xffffffff));
      else if (difftime(lease->expires, now) > 0.0)
	CHECK(blobmsg_add_u32(&b, "expires", (uint32_t)difftime(lease->expires, now)));
      else
	CHECK(blobmsg_add_u32(&b, "expires", 0));

      if (lease->clid && lease->clid_len > 0)
	{
	  /* 255 * 3 = 765 < MAXDNAME */
	  char *clid_str = daemon->namebuff;
	  for (i = 0; i < lease->clid_len && i < 255; i++)
	    sprintf(clid_str + i * 3, "%02x:", lease->clid[i]);
	  clid_str[lease->clid_len * 3 - 1] = '\0';
	  CHECK(blobmsg_add_string(&b, "client_id", clid_str));
	}

      blobmsg_close_table(&b, table);
    }

  blobmsg_close_array(&b, array);
  CHECK(ubus_send_reply(ctx, req, b.head));

  return UBUS_STATUS_OK;
}
#endif

#ifdef HAVE_CONNTRACK
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg)
{
  const struct blobmsg_policy *policy = set_connmark_allowlist_policy;
  size_t policy_len = countof(set_connmark_allowlist_policy);
  struct allowlist *allowlists = NULL, **allowlists_pos;
  char **patterns = NULL, **patterns_pos;
  u32 mark, mask = UINT32_MAX;
  size_t num_patterns = 0;
  struct blob_attr *tb[policy_len];
  struct blob_attr *attr;

  (void)ctx;
  (void)obj;
  (void)req;
  (void)method;
  
  if (blobmsg_parse(policy, policy_len, tb, blob_data(msg), blob_len(msg)))
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (!tb[SET_CONNMARK_ALLOWLIST_MARK])
    return UBUS_STATUS_INVALID_ARGUMENT;
  mark = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MARK]);
  if (!mark)
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (tb[SET_CONNMARK_ALLOWLIST_MASK])
    {
      mask = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MASK]);
      if (!mask || (mark & ~mask))
	return UBUS_STATUS_INVALID_ARGUMENT;
    }
  
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (blob_id(attr) != BLOBMSG_TYPE_STRING)
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (!(pattern = blobmsg_get_string(attr)))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (strcmp(pattern, "*") && !is_valid_dns_name_pattern(pattern))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  num_patterns++;
	}
    }
  
  for (allowlists_pos = &daemon->allowlists; *allowlists_pos; allowlists_pos = &(*allowlists_pos)->next)
    if ((*allowlists_pos)->mark == mark && (*allowlists_pos)->mask == mask)
      {
	struct allowlist *allowlists_next = (*allowlists_pos)->next;
	for (patterns_pos = (*allowlists_pos)->patterns; *patterns_pos; patterns_pos++)
	  {
	    free(*patterns_pos);
	    *patterns_pos = NULL;
	  }
	free((*allowlists_pos)->patterns);
	(*allowlists_pos)->patterns = NULL;
	free(*allowlists_pos);
	*allowlists_pos = allowlists_next;
	break;
      }
  
  if (!num_patterns)
    return UBUS_STATUS_OK;
  
  patterns = whine_malloc((num_patterns + 1) * sizeof(char *));
  if (!patterns)
    goto fail;
  patterns_pos = patterns;
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (!(pattern = blobmsg_get_string(attr)))
	    goto fail;
	  if (!(*patterns_pos = whine_malloc(strlen(pattern) + 1)))
	    goto fail;
	  strcpy(*patterns_pos++, pattern);
	}
    }
  
  allowlists = whine_malloc(sizeof(struct allowlist));
  if (!allowlists)
    goto fail;
  memset(allowlists, 0, sizeof(struct allowlist));
  allowlists->mark = mark;
  allowlists->mask = mask;
  allowlists->patterns = patterns;
  allowlists->next = daemon->allowlists;
  daemon->allowlists = allowlists;
  return UBUS_STATUS_OK;
  
fail:
  if (patterns)
    {
      for (patterns_pos = patterns; *patterns_pos; patterns_pos++)
	{
	  free(*patterns_pos);
	  *patterns_pos = NULL;
	}
      free(patterns);
      patterns = NULL;
    }
  if (allowlists)
    {
      free(allowlists);
      allowlists = NULL;
    }
  return UBUS_STATUS_UNKNOWN_ERROR;
}
#endif

#undef CHECK

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return; \
      } \
  } while (0)

void ubus_event_bcast(const char *type, const char *mac, const char *ip, const char *name, const char *interface)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));
  if (mac)
    CHECK(blobmsg_add_string(&b, "mac", mac));
  if (ip)
    CHECK(blobmsg_add_string(&b, "ip", ip));
  if (name)
    CHECK(blobmsg_add_string(&b, "name", name));
  if (interface)
    CHECK(blobmsg_add_string(&b, "interface", interface));
  
  CHECK(ubus_notify(ubus, &ubus_object, type, b.head, -1));
}

#ifdef HAVE_CONNTRACK
void ubus_event_bcast_connmark_allowlist_refused(u32 mark, const char *name)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.refused", b.head, -1));
}

void ubus_event_bcast_connmark_allowlist_resolved(u32 mark, const char *name, const char *value, u32 ttl)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  CHECK(blobmsg_add_string(&b, "value", value));
  CHECK(blobmsg_add_u32(&b, "ttl", ttl));
  
  /* Set timeout to allow UBus subscriber to configure firewall rules before returning. */
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.resolved", b.head, /* timeout: */ 1000));
}
#endif

#undef CHECK

#endif /* HAVE_UBUS */
