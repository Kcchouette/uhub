/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"
#include "inf.h"

struct hub_info* g_hub = 0;

/* Forward declarations for static functions */
static void hub_hbri_timeout_callback(struct timeout_evt* t);

/* FIXME: Flood control should be done in a plugin! */
#define CHECK_FLOOD(TYPE, WARN) \
	if (flood_control_check(&u->flood_ ## TYPE , hub->config->flood_ctl_  ## TYPE, hub->config->flood_ctl_interval, net_get_time()) &&  !auth_cred_is_unrestricted(u->credentials)) \
	{ \
		if (WARN) \
		{ \
			hub_send_flood_warning(hub, u, hub->config->msg_user_flood_ ## TYPE); \
		} \
		break; \
	}

#define ROUTE_MSG() \
	if (user_is_logged_in(u)) \
	{ \
		ret = route_message(hub, u, cmd); \
	} \
	else \
	{ \
		ret = -1; \
	}

int hub_handle_message(struct hub_info* hub, struct hub_user* u, const char* line, size_t length)
{
	int ret = 0;
	struct adc_message* cmd = 0;

	LOG_PROTO("recv %s: %s", sid_to_string(u->id.sid), line);

	if (user_is_disconnecting(u))
		return -1;

	cmd = adc_msg_parse_verify(u, line, length);
	if (cmd)
	{
		switch (cmd->cmd)
		{
			case ADC_CMD_HSUP:
				CHECK_FLOOD(extras, 0);
				ret = hub_handle_support(hub, u, cmd);
				break;

			case ADC_CMD_HPAS:
				CHECK_FLOOD(extras, 0);
				ret = hub_handle_password(hub, u, cmd);
				break;

			case ADC_CMD_BINF:
				CHECK_FLOOD(update, 1);
				ret = hub_handle_info(hub, u, cmd);
				break;

			case ADC_CMD_DINF:
			case ADC_CMD_EINF:
			case ADC_CMD_FINF:
			case ADC_CMD_BQUI:
			case ADC_CMD_DQUI:
			case ADC_CMD_EQUI:
			case ADC_CMD_FQUI:
				/* these must never be allowed for security reasons, so we ignore them. */
				CHECK_FLOOD(extras, 1);
				break;

			case ADC_CMD_EMSG:
			case ADC_CMD_DMSG:
			case ADC_CMD_BMSG:
			case ADC_CMD_FMSG:
				CHECK_FLOOD(chat, 1);
				ret = hub_handle_chat_message(hub, u, cmd);
				break;

			case ADC_CMD_BSCH:
			case ADC_CMD_DSCH:
			case ADC_CMD_ESCH:
			case ADC_CMD_FSCH:
				cmd->priority = -1;
				if (plugin_handle_search(hub, u, cmd->cache) == st_deny)
					break;
				CHECK_FLOOD(search, 1);
				ROUTE_MSG();
				break;

			case ADC_CMD_FRES: // spam
			case ADC_CMD_BRES: // spam
			case ADC_CMD_ERES: // pointless.
				CHECK_FLOOD(extras, 1);
				break;

			case ADC_CMD_DRES:
				cmd->priority = -1;
				if (plugin_handle_search_result(hub, u, uman_get_user_by_sid(hub->users, cmd->target), cmd->cache) == st_deny)
					break;
				/* CHECK_FLOOD(search, 0); */
				ROUTE_MSG();
				break;

			case ADC_CMD_DRCM:
				cmd->priority = -1;
				if (plugin_handle_revconnect(hub, u, uman_get_user_by_sid(hub->users, cmd->target)) == st_deny)
					break;
				CHECK_FLOOD(connect, 1);
				ROUTE_MSG();
				break;

			case ADC_CMD_DCTM:
				cmd->priority = -1;
				if (plugin_handle_connect(hub, u, uman_get_user_by_sid(hub->users, cmd->target)) == st_deny)
					break;
				CHECK_FLOOD(connect, 1);
				ROUTE_MSG();
				break;

			case ADC_CMD_BCMD:
			case ADC_CMD_DCMD:
			case ADC_CMD_ECMD:
			case ADC_CMD_FCMD:
			case ADC_CMD_HCMD:
				CHECK_FLOOD(extras, 1);
				break;

			case ADC_CMD_TCP:
				CHECK_FLOOD(extras, 0);
				ret = hub_handle_tcp(hub, u, cmd);
				break;

			default:
				CHECK_FLOOD(extras, 1);
				ROUTE_MSG();
		}
		adc_msg_free(cmd);
	}
	else
	{
		if (!user_is_logged_in(u))
		{
			ret = -1;
		}
	}

	return ret;
}


int hub_handle_support(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	int ret = 0;
	int index = 0;
	int ok = 1;
	char* arg = adc_msg_get_argument(cmd, index);

	if (hub->status == hub_status_disabled && u->state == state_protocol)
	{
		on_login_failure(hub, u, status_msg_hub_disabled);
		hub_free(arg);
		return -1;
	}

	while (arg)
	{
		if (strlen(arg) == 6)
		{
			fourcc_t fourcc = FOURCC(arg[2], arg[3], arg[4], arg[5]);
			if (strncmp(arg, ADC_SUP_FLAG_ADD, 2) == 0)
			{
				user_support_add(u, fourcc);
			}
			else if (strncmp(arg, ADC_SUP_FLAG_REMOVE, 2) == 0)
			{
				user_support_remove(u, fourcc);
			}
			else
			{
				ok = 0;
			}
		}
		else
		{
			ok = 0;
		}

		index++;
		hub_free(arg);
		arg = adc_msg_get_argument(cmd, index);
	}

	if (u->state == state_protocol)
	{
		if (index == 0) ok = 0; /* Need to support *SOMETHING*, at least BASE */
		if (!ok)
		{
			/* disconnect user. Do not send crap during initial handshake! */
			hub_disconnect_user(hub, u, quit_logon_error);
			return -1;
		}

		if (user_flag_get(u, feature_base))
		{
			/* User supports ADC/1.0 and a hash we know */
			if (user_flag_get(u, feature_tiger))
			{
				hub_send_handshake(hub, u);
				net_con_set_timeout(u->connection, TIMEOUT_HANDSHAKE);
			}
			else
			{
				// no common hash algorithm.
				hub_send_status(hub, u, status_msg_proto_no_common_hash, status_level_fatal);
				hub_disconnect_user(hub, u, quit_protocol_error);
			}
		}
		else if (user_flag_get(u, feature_bas0))
		{
			if (hub->config->obsolete_clients)
			{
				hub_send_handshake(hub, u);
				net_con_set_timeout(u->connection, TIMEOUT_HANDSHAKE);
			}
			else
			{
				/* disconnect user for using an obsolete client. */
				char* tmp = adc_msg_escape(hub->config->msg_proto_obsolete_adc0);
				struct adc_message* message = adc_msg_construct(ADC_CMD_IMSG, 6 + strlen(tmp));
				adc_msg_add_argument(message, tmp);
				hub_free(tmp);
				route_to_user(hub, u, message);
				adc_msg_free(message);
				hub_disconnect_user(hub, u, quit_protocol_error);
			}
		}
		else
		{
			/* Not speaking a compatible protocol - just disconnect. */
			hub_disconnect_user(hub, u, quit_logon_error);
		}
	}

	return ret;
}


int hub_handle_password(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* password = adc_msg_get_argument(cmd, 0);
	int ret = 0;

	if (u->state == state_verify)
	{
		if (acl_password_verify(hub, u, password))
		{
			on_login_success(hub, u);
		}
		else
		{
			on_login_failure(hub, u, status_msg_auth_invalid_password);
			ret = -1;
		}
	}

	hub_free(password);
	return ret;
}


int hub_handle_chat_message(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* message = adc_msg_get_argument(cmd, 0);
	char* message_decoded = NULL;
	int ret = 0;
	int relay = 1;
	int broadcast;
	int private_msg;
	int command;
	int offset;

	if (!message)
		return 0;

	message_decoded = adc_msg_unescape(message);
	if (!message_decoded)
	{
		hub_free(message);
		return 0;
	}

	if (!user_is_logged_in(u))
	{
		hub_free(message_decoded);
		hub_free(message);
		return 0;
	}

	broadcast = (cmd->cache[0] == 'B');
	private_msg = (cmd->cache[0] == 'D' || cmd->cache[0] == 'E');
	command = (message[0] == '!' || message[0] == '+');

	if (broadcast && command)
	{
		/*
		 * A message such as "++message" is handled as "+message", by removing the first character.
		 * The first character is removed by memmoving the string one byte to the left.
		 */
		if (message[1] == message[0])
		{
			relay = 1;
			offset = adc_msg_get_arg_offset(cmd);
			memmove(cmd->cache+offset+1, cmd->cache+offset+2, cmd->length - offset);
			cmd->length--;
		}
		else
		{
			relay = command_invoke(hub->commands, u, message_decoded);
		}
	}

	if (relay && broadcast && user_flag_get(u, flag_muted))
	{
		relay = 0;
	}

	if (relay)
	{
		plugin_st status = st_default;
		if (broadcast)
		{
			status = plugin_handle_chat_message(hub, u, message_decoded, 0);
		}
		else if (private_msg)
		{
			struct hub_user* target = uman_get_user_by_sid(hub->users, cmd->target);
			if (target)
				status = plugin_handle_private_message(hub, u, target, message_decoded, 0);
			else
				relay = 0;
		}

		if (status == st_deny)
			relay = 0;
	}

	if (relay)
	{
		/* adc_msg_remove_named_argument(cmd, "PM"); */
		if (broadcast)
		{
			plugin_log_chat_message(hub, u, message_decoded, 0);
		}
		ret = route_message(hub, u, cmd);
	}
	hub_free(message);
	hub_free(message_decoded);
	return ret;
}

void hub_send_support(struct hub_info* hub, struct hub_user* u)
{
	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, hub->command_support);
	}
}


void hub_send_sid(struct hub_info* hub, struct hub_user* u)
{
	sid_t sid;
	struct adc_message* command;
	if (user_is_connecting(u))
	{
		command = adc_msg_construct(ADC_CMD_ISID, 10);
		sid = uman_get_free_sid(hub->users, u);
		adc_msg_add_argument(command, (const char*) sid_to_string(sid));
		route_to_user(hub, u, command);
		adc_msg_free(command);
	}
}


void hub_send_ping(struct hub_info* hub, struct hub_user* user)
{
	/* This will just send a newline, despite appearing to do more below. */
	struct adc_message* ping = adc_msg_construct(0, 0);
	ping->cache[0]     = '\n';
	ping->cache[1]     = 0;
	ping->length       = 1;
	ping->priority     = 1;
	route_to_user(hub, user, ping);
	adc_msg_free(ping);
}


void hub_send_hubinfo(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* info = adc_msg_copy(hub->command_info);
	int value = 0;
	uint64_t size = 0;

	if (user_flag_get(u, feature_ping))
	{
/*
		FIXME: These are missing:
		HH - Hub Host address ( DNS or IP )
		WS - Hub Website
		NE - Hub Network
		OW - Hub Owner name
*/
		adc_msg_add_named_argument(info, "UC", uhub_itoa(hub_get_user_count(hub)));
		adc_msg_add_named_argument(info, "MC", uhub_itoa(hub_get_max_user_count(hub)));
		adc_msg_add_named_argument(info, "SS", uhub_ulltoa(hub_get_shared_size(hub)));
		adc_msg_add_named_argument(info, "SF", uhub_ulltoa(hub_get_shared_files(hub)));

		/* Maximum/minimum share size */
		size = hub_get_max_share(hub);
		if (size) adc_msg_add_named_argument(info, "XS", uhub_ulltoa(size));
		size = hub_get_min_share(hub);
		if (size) adc_msg_add_named_argument(info, "MS", uhub_ulltoa(size));

		/* Maximum/minimum upload slots allowed per user */
		value = hub_get_max_slots(hub);
		if (value) adc_msg_add_named_argument(info, "XL", uhub_itoa(value));
		value = hub_get_min_slots(hub);
		if (value) adc_msg_add_named_argument(info, "ML", uhub_itoa(value));

		/* guest users must be on min/max hubs */
		value = hub_get_max_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "XU", uhub_itoa(value));
		value = hub_get_min_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "MU", uhub_itoa(value));

		/* registered users must be on min/max hubs */
		value = hub_get_max_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "XR", uhub_itoa(value));
		value = hub_get_min_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "MR", uhub_itoa(value));

		/* operators must be on min/max hubs */
		value = hub_get_max_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "XO", uhub_itoa(value));
		value = hub_get_min_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "MO", uhub_itoa(value));

		/* uptime in seconds */
		adc_msg_add_named_argument(info, "UP", uhub_itoa((int) difftime(time(0), hub->tm_started)));
	}

	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, info);
	}
	adc_msg_free(info);

	/* Only send banner when connecting */
	if (hub->config->show_banner && user_is_connecting(u))
	{
		route_to_user(hub, u, hub->command_banner);
	}
}

void hub_send_handshake(struct hub_info* hub, struct hub_user* u)
{
	user_flag_set(u, flag_pipeline);
	hub_send_support(hub, u);
	hub_send_sid(hub, u);
	hub_send_hubinfo(hub, u);
	route_flush_pipeline(hub, u);

	if (!user_is_disconnecting(u))
	{
		user_set_state(u, state_identify);
	}
}

void hub_send_password_challenge(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* igpa;
	igpa = adc_msg_construct(ADC_CMD_IGPA, 38);
	adc_msg_add_argument(igpa, acl_password_generate_challenge(hub, u));
	user_set_state(u, state_verify);
	route_to_user(hub, u, igpa);
	adc_msg_free(igpa);
}

void hub_send_flood_warning(struct hub_info* hub, struct hub_user* u, const char* message)
{
	struct adc_message* msg;

	if (user_flag_get(u, flag_flood))
		return;

	msg = adc_msg_construct(ADC_CMD_ISTA, 128);
	if (msg)
	{
		adc_msg_add_argument(msg, "110");
		adc_msg_add_argument_string(msg, message);

		route_to_user(hub, u, msg);
		user_flag_set(u, flag_flood);
		adc_msg_free(msg);
	}
}

static int check_duplicate_logins_ok(struct hub_info* hub, struct hub_user* user)
{
	struct hub_user* lookup1;
	struct hub_user* lookup2;

	lookup1 = uman_get_user_by_nick(hub->users, user->id.nick);
	if (lookup1)
		return status_msg_inf_error_nick_taken;

	lookup2 = uman_get_user_by_cid(hub->users, user->id.cid);
	if (lookup2)
		return status_msg_inf_error_cid_taken;

	return 0;
}

static void hub_event_dispatcher(void* callback_data, struct event_data* message)
{
	int status;
	struct hub_info* hub = (struct hub_info*) callback_data;
	struct hub_user* user = (struct hub_user*) message->ptr;
	uhub_assert(hub != NULL);

	switch (message->id)
	{
		case UHUB_EVENT_USER_JOIN:
			if (user_is_disconnecting(user))
				break;

			if (message->flags)
			{
				hub_send_password_challenge(hub, user);
			}
			else
			{
				/* Race condition, we could have two messages for two logins queued up.
				   So make sure we don't let the second client in. */
				status = check_duplicate_logins_ok(hub, user);
				if (!status)
				{
					on_login_success(hub, user);
				}
				else
				{
					on_login_failure(hub, user, (enum status_message) status);
				}
			}
			break;

		case UHUB_EVENT_USER_QUIT:
			uman_remove(hub->users, user);
			uman_send_quit_message(hub, hub->users, user);
			on_logout_user(hub, user);
			hub_schedule_destroy_user(hub, user);
			break;

		case UHUB_EVENT_USER_DESTROY:
			user_destroy(user);
			break;

		case UHUB_EVENT_HUB_SHUTDOWN:
			user = (struct hub_user*) list_get_first(hub->users->list);
			while (user)
			{
				uman_remove(hub->users, user);
				user_destroy(user);
				user = (struct hub_user*) list_get_first(hub->users->list);
			}
			break;


		default:
			/* FIXME: ignored */
			break;
	}
}


static void hub_update_stats(struct hub_info* hub)
{
	const int factor = TIMEOUT_STATS;
	struct net_statistics* total;
	struct net_statistics* intermediate;
	net_stats_get(&intermediate, &total);

	hub->stats.net_tx = (intermediate->tx / factor);
	hub->stats.net_rx = (intermediate->rx / factor);
	hub->stats.net_tx_peak = MAX(hub->stats.net_tx, hub->stats.net_tx_peak);
	hub->stats.net_rx_peak = MAX(hub->stats.net_rx, hub->stats.net_rx_peak);
	hub->stats.net_tx_total = total->tx;
	hub->stats.net_rx_total = total->rx;

	net_stats_reset();
}

static void hub_timer_statistics(struct timeout_evt* t)
{
	struct hub_info* hub = (struct hub_info*) t->ptr;
	hub_update_stats(hub);
	timeout_queue_reschedule(net_backend_get_timeout_queue(), hub->stats.timeout, TIMEOUT_STATS);
}

static struct net_connection* start_listening_socket(const char* bind_addr, uint16_t port, int backlog, struct hub_info* hub)
{
	struct net_connection* server;
	struct sockaddr_storage addr;
	socklen_t sockaddr_size;
	int sd, ret;

	if (ip_convert_address(bind_addr, port, (struct sockaddr*) &addr, &sockaddr_size) == -1)
	{
		return 0;
	}

	sd = net_socket_create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1)
	{
		return 0;
	}

	if ((net_set_reuseaddress(sd, 1) == -1) || (net_set_nonblocking(sd, 1) == -1))
	{
		net_close(sd);
		return 0;
	}

	ret = net_bind(sd, (struct sockaddr*) &addr, sockaddr_size);
	if (ret == -1)
	{
		LOG_ERROR("hub_start_service(): Unable to bind to TCP local address. errno=%d, str=%s", net_error(), net_error_string(net_error()));
		net_close(sd);
		return 0;
	}

	ret = net_listen(sd, backlog);
	if (ret == -1)
	{
		LOG_ERROR("hub_start_service(): Unable to listen to socket");
		net_close(sd);
		return 0;
	}

	server = net_con_create();
	net_con_initialize(server, sd, net_on_accept, hub, NET_EVENT_READ);

	return server;
}

struct server_alt_port_data
{
	struct hub_info* hub;
	struct hub_config* config;
};

static int server_alt_port_start_one(char* line, int count, void* ptr)
{
	struct server_alt_port_data* data = (struct server_alt_port_data*) ptr;

	int port = uhub_atoi(line);
	struct net_connection* con = start_listening_socket(data->config->server_bind_addr, port, data->config->server_listen_backlog, data->hub);
	if (con)
	{
		list_append(data->hub->server_alt_ports, con);
		LOG_INFO("Listening on alternate port %d...", port);
		return 0;
	}
	return -1;
}

static void server_alt_port_start(struct hub_info* hub, struct hub_config* config)
{
	struct server_alt_port_data data;

	if (!config->server_alt_ports || !*config->server_alt_ports)
		return;

	hub->server_alt_ports = (struct linked_list*) list_create();

	data.hub = hub;
	data.config = config;

	string_split(config->server_alt_ports, ",", &data, server_alt_port_start_one);
}

static void server_alt_port_clear(void* ptr)
{
	struct net_connection* con = (struct net_connection*) ptr;
	if (con)
	{
		net_con_close(con);
		hub_free(con);
	}
}

static void server_alt_port_stop(struct hub_info* hub)
{
	if (hub->server_alt_ports)
	{
		list_clear(hub->server_alt_ports, &server_alt_port_clear);
		list_destroy(hub->server_alt_ports);
	}
}

#ifdef SSL_SUPPORT
static int load_ssl_certificates(struct hub_info* hub, struct hub_config* config)
{
	if (!config->tls_enable)
		return 1;

	hub->ctx = net_ssl_context_create(config->tls_version, config->tls_cipher_list, config->tls_ciphersuites);

	if (!hub->ctx)
	  return 0;

	if (!ssl_load_certificate(hub->ctx, config->tls_certificate))
		return 0;

	if (!ssl_load_private_key(hub->ctx, config->tls_private_key))
		return 0;

	if (!ssl_check_private_key(hub->ctx))
		return 0;

	LOG_INFO("Enabling TLS (%s), using certificate: %s, private key: %s", net_ssl_get_provider(), config->tls_certificate, config->tls_private_key);

	ssl_keyprint_info(hub->ctx, config->server_port);

	return 1;
}

static void unload_ssl_certificates(struct hub_info* hub)
{
	if (hub->ctx)
		net_ssl_context_destroy(hub->ctx);
}
#endif /* SSL_SUPPORT */

struct hub_info* hub_start_service(struct hub_config* config)
{
	struct hub_info* hub = 0;
	int ipv6_supported;

	hub = hub_malloc_zero(sizeof(struct hub_info));
	if (!hub)
	{
		LOG_FATAL("Unable to allocate memory for hub");
		return 0;
	}

	hub->tm_started = time(0);
	ipv6_supported = net_is_ipv6_supported();
	if (ipv6_supported)
		LOG_DEBUG("IPv6 supported.");
	else
		LOG_DEBUG("IPv6 not supported.");

	hub->server = start_listening_socket(config->server_bind_addr, config->server_port, config->server_listen_backlog, hub);
	if (!hub->server)
	{
		hub_free(hub);
		LOG_FATAL("Unable to start hub service");
		return 0;
	}
	LOG_INFO("Starting " PRODUCT "/" VERSION ", listening on %s:%d...", net_get_local_address(hub->server->sd), config->server_port);

#ifdef SSL_SUPPORT
	if (!load_ssl_certificates(hub, config))
	{
		hub_free(hub);
		return 0;
	}
#endif

	hub->config = config;
	hub->users = NULL;

	hub->users = uman_init();
	if (!hub->users)
	{
		net_con_close(hub->server);
		hub_free(hub);
		return 0;
	}

	if (event_queue_initialize(&hub->queue, hub_event_dispatcher, (void*) hub) == -1)
	{
		net_con_close(hub->server);
		uman_shutdown(hub->users);
		hub_free(hub);
		return 0;
	}

	hub->recvbuf = hub_malloc(MAX_RECV_BUF);
	hub->sendbuf = hub_malloc(MAX_SEND_BUF);
	if (!hub->recvbuf || !hub->sendbuf)
	{
		net_con_close(hub->server);
		hub_free(hub->recvbuf);
		hub_free(hub->sendbuf);
		uman_shutdown(hub->users);
		hub_free(hub);
		return 0;
	}

	server_alt_port_start(hub, config);

	hub->status = hub_status_running;

	// Initialize HBRI pending validations list
	hub->hbri_pending = list_create();
	if (!hub->hbri_pending)
	{
		LOG_ERROR("Unable to allocate memory for HBRI pending list");
		net_con_close(hub->server);
		hub_free(hub->recvbuf);
		hub_free(hub->sendbuf);
		uman_shutdown(hub->users);
		hub_free(hub);
		return 0;
	}

	g_hub = hub;

	if (net_backend_get_timeout_queue())
	{
		hub->stats.timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		timeout_evt_initialize(hub->stats.timeout, hub_timer_statistics, hub);
		timeout_queue_insert(net_backend_get_timeout_queue(), hub->stats.timeout, TIMEOUT_STATS);
	}

	// Initialize HBRI timeout handler
	if (net_backend_get_timeout_queue())
	{
		hub->hbri_timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		if (hub->hbri_timeout)
		{
			timeout_evt_initialize(hub->hbri_timeout, hub_hbri_timeout_callback, hub);
			timeout_queue_insert(net_backend_get_timeout_queue(), hub->hbri_timeout, 1); // Check every second
		}
	}

	// Start the hub command sub-system
	hub->commands = command_initialize(hub);
	return hub;
}


void hub_shutdown_service(struct hub_info* hub)
{
	LOG_DEBUG("hub_shutdown_service()");

	if (net_backend_get_timeout_queue())
	{
		timeout_queue_remove(net_backend_get_timeout_queue(), hub->stats.timeout);
		hub_free(hub->stats.timeout);
	}

#ifdef SSL_SUPPORT
	unload_ssl_certificates(hub);
#endif

	event_queue_shutdown(hub->queue);
	net_con_close(hub->server);
	server_alt_port_stop(hub);
	uman_shutdown(hub->users);
	hub->status = hub_status_stopped;

	// Clean up HBRI pending list
	if (hub->hbri_pending)
	{
		list_clear(hub->hbri_pending, NULL); // Entries will be freed below
		list_destroy(hub->hbri_pending);
	}

	// Clean up HBRI timeout handler
	if (hub->hbri_timeout)
	{
		if (timeout_evt_is_scheduled(hub->hbri_timeout))
		{
			timeout_queue_remove(net_backend_get_timeout_queue(), hub->hbri_timeout);
		}
		hub_free(hub->hbri_timeout);
	}

	hub_free(hub->sendbuf);
	hub_free(hub->recvbuf);
	command_shutdown(hub->commands);
	hub_free(hub);
	hub = 0;
	g_hub = 0;
}

int hub_plugins_load(struct hub_info* hub)
{
	if (!hub->config->file_plugins || !*hub->config->file_plugins)
		return 0;

	hub->plugins = hub_malloc_zero(sizeof(struct uhub_plugins));
	if (!hub->plugins)
		return -1;

	if (plugin_initialize(hub->config, hub) < 0)
	{
		hub_free(hub->plugins);
		hub->plugins = 0;
		return -1;
	}
	return 0;
}

void hub_plugins_unload(struct hub_info* hub)
{
	if (hub->plugins)
	{
		plugin_shutdown(hub->plugins);
		hub_free(hub->plugins);
		hub->plugins = 0;
	}
}

void hub_set_variables(struct hub_info* hub, struct acl_handle* acl)
{
	char* tmp;
	char* server = adc_msg_escape(PRODUCT_STRING); /* FIXME: OOM */

	hub->acl = acl;
	hub->command_info = adc_msg_construct(ADC_CMD_IINF, 15);
	if (hub->command_info)
	{
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_CLIENT_TYPE, ADC_CLIENT_TYPE_HUB);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_USER_AGENT_PRODUCT, PRODUCT);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_USER_AGENT_VERSION, GIT_VERSION);

		adc_msg_add_named_argument_string(hub->command_info, ADC_INF_FLAG_NICK, hub->config->hub_name);

		adc_msg_add_named_argument_string(hub->command_info, ADC_INF_FLAG_DESCRIPTION, hub->config->hub_description);

		if (*hub->config->failover_redirect_addr)
			adc_msg_add_named_argument_string(hub->command_info, ADC_INF_FLAG_FAILOVER_ADDR, hub->config->failover_redirect_addr);
	}

	/* Build support message with optional HBRI support */
	if (hub->config->hbri_enable)
	{
		hub->command_support = adc_msg_construct(ADC_CMD_ISUP, 6 + strlen(ADC_PROTO_SUPPORT) + 7); /* +7 for " ADHBRI" */
		if (hub->command_support)
		{
			adc_msg_add_argument(hub->command_support, ADC_PROTO_SUPPORT " ADHBRI");
		}
	}
	else
	{
		hub->command_support = adc_msg_construct(ADC_CMD_ISUP, 6 + strlen(ADC_PROTO_SUPPORT));
		if (hub->command_support)
		{
			adc_msg_add_argument(hub->command_support, ADC_PROTO_SUPPORT);
		}
	}

	hub->command_banner = adc_msg_construct(ADC_CMD_ISTA, 100 + strlen(server));
	if (hub->command_banner)
	{
		if (hub->config->show_banner_sys_info)
			tmp = "Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO;
		else
			tmp = "Powered by " PRODUCT_STRING;
		adc_msg_add_argument(hub->command_banner, "000");
		adc_msg_add_argument_string(hub->command_banner, tmp);
	}

	if (hub_plugins_load(hub) < 0)
	{
		LOG_FATAL("Unable to load plugins.");
		hub->status = hub_status_shutdown;
	}
	else
	{
		hub->status = (hub->config->hub_enabled ? hub_status_running : hub_status_disabled);
	}

	hub_free(server);
}


void hub_free_variables(struct hub_info* hub)
{
	hub_plugins_unload(hub);

	adc_msg_free(hub->command_info);
	adc_msg_free(hub->command_banner);
	adc_msg_free(hub->command_support);
}

static void set_status_code(enum msg_status_level level, int code, char buffer[4])
{
	buffer[0] = ('0' + (int) level);
	buffer[1] = ('0' + (code / 10));
	buffer[2] = ('0' + (code % 10));
	buffer[3] = 0;
}

/**
 * @param hub The hub instance this message is sent from.
 * @param user The user this message is sent to.
 * @param msg See enum status_message
 * @param level See enum status_level
 */
void hub_send_status(struct hub_info* hub, struct hub_user* user, enum status_message msg, enum msg_status_level level)
{
	struct hub_config* cfg = hub->config;
	struct adc_message* cmd = adc_msg_construct(ADC_CMD_ISTA, 6);
	struct adc_message* qui = adc_msg_construct(ADC_CMD_IQUI, 512);
	char code[4];
	char buf[256];
	const char* text = 0;
	const char* flag = 0;
	char* escaped_text = 0;
	int reconnect_time = 0;
	int redirect = 0;

	if (!cmd || !qui)
	{
		adc_msg_free(cmd);
		adc_msg_free(qui);
		return;
	}

#define STATUS(CODE, MSG, FLAG, RCONTIME, REDIRECT) case status_ ## MSG : set_status_code(level, CODE, code); text = cfg->MSG; flag = FLAG; reconnect_time = RCONTIME; redirect = REDIRECT; break
	switch (msg)
	{
		STATUS(11, msg_hub_full, 0, 600, 1); /* FIXME: Proper timeout? */
		STATUS(12, msg_hub_disabled, 0, -1, 1);
		STATUS(26, msg_hub_registered_users_only, 0, 0, 1);
		STATUS(43, msg_inf_error_nick_missing, 0, 0, 0);
		STATUS(43, msg_inf_error_nick_multiple, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_invalid, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_long, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_short, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_spaces, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_bad_chars, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_not_utf8, 0, 0, 0);
		STATUS(22, msg_inf_error_nick_taken, 0, 0, 0);
		STATUS(21, msg_inf_error_nick_restricted, 0, 0, 0);
		STATUS(43, msg_inf_error_cid_invalid, "FBID", 0, 0);
		STATUS(43, msg_inf_error_cid_missing, "FMID", 0, 0);
		STATUS(24, msg_inf_error_cid_taken, 0, 0, 0);
		STATUS(43, msg_inf_error_pid_missing, "FMPD", 0, 0);
		STATUS(27, msg_inf_error_pid_invalid, "FBPD", 0, 0);
		STATUS(31, msg_ban_permanently, 0, 0, 0);
		STATUS(32, msg_ban_temporarily, "TL600", 600, 0); /* FIXME: Proper timeout? */
		STATUS(23, msg_auth_invalid_password, 0, 0, 0);
		STATUS(20, msg_auth_user_not_found, 0, 0, 0);
		STATUS(30, msg_error_no_memory, 0, 0, 1);
		STATUS(43, msg_user_share_size_low,   "FB" ADC_INF_FLAG_SHARED_SIZE, 0, 1);
		STATUS(43, msg_user_share_size_high,  "FB" ADC_INF_FLAG_SHARED_SIZE, 0, 1);
		STATUS(43, msg_user_slots_low,        "FB" ADC_INF_FLAG_UPLOAD_SLOTS, 0, 1);
		STATUS(43, msg_user_slots_high,       "FB" ADC_INF_FLAG_UPLOAD_SLOTS, 0, 1);
		STATUS(43, msg_user_hub_limit_low, 0, 0, 1);
		STATUS(43, msg_user_hub_limit_high, 0, 0, 1);
		STATUS(47, msg_proto_no_common_hash, 0, -1, 1);
		STATUS(40, msg_proto_obsolete_adc0, 0, -1, 1);
		STATUS(55, msg_hbri_timeout, 0, 0, 0);
		STATUS(56, msg_hbri_validation_failed, 0, 0, 0);
		STATUS(57, msg_hbri_ip_mismatch, 0, 0, 0);
	}
#undef STATUS

	escaped_text = adc_msg_escape(text);

	adc_msg_add_argument(cmd, code);
	adc_msg_add_argument(cmd, escaped_text);

	if (flag)
	{
		adc_msg_add_argument(cmd, flag);
	}

	route_to_user(hub, user, cmd);

	if (level >= status_level_fatal)
	{
		adc_msg_add_argument(qui, sid_to_string(user->id.sid));

		snprintf(buf, 230, "MS%s", escaped_text);
		adc_msg_add_argument(qui, buf);

		if (reconnect_time != 0)
		{
			snprintf(buf, 10, "TL%d", reconnect_time);
			adc_msg_add_argument(qui, buf);
		}

		if (redirect && *hub->config->redirect_addr)
		{
			snprintf(buf, 255, "RD%s", hub->config->redirect_addr);
			adc_msg_add_argument(qui, buf);
		}
		route_to_user(hub, user, qui);
	}

	hub_free(escaped_text);
	adc_msg_free(cmd);
	adc_msg_free(qui);
}

const char* hub_get_status_message(struct hub_info* hub, enum status_message msg)
{
#define STATUS(MSG) case status_ ## MSG : return cfg->MSG
	struct hub_config* cfg = hub->config;
	switch (msg)
	{
		STATUS(msg_hub_full);
		STATUS(msg_hub_disabled);
		STATUS(msg_hub_registered_users_only);
		STATUS(msg_inf_error_nick_missing);
		STATUS(msg_inf_error_nick_multiple);
		STATUS(msg_inf_error_nick_invalid);
		STATUS(msg_inf_error_nick_long);
		STATUS(msg_inf_error_nick_short);
		STATUS(msg_inf_error_nick_spaces);
		STATUS(msg_inf_error_nick_bad_chars);
		STATUS(msg_inf_error_nick_not_utf8);
		STATUS(msg_inf_error_nick_taken);
		STATUS(msg_inf_error_nick_restricted);
		STATUS(msg_inf_error_cid_invalid);
		STATUS(msg_inf_error_cid_missing);
		STATUS(msg_inf_error_cid_taken);
		STATUS(msg_inf_error_pid_missing);
		STATUS(msg_inf_error_pid_invalid);
		STATUS(msg_ban_permanently);
		STATUS(msg_ban_temporarily);
		STATUS(msg_auth_invalid_password);
		STATUS(msg_auth_user_not_found);
		STATUS(msg_error_no_memory);
		STATUS(msg_user_share_size_low);
		STATUS(msg_user_share_size_high);
		STATUS(msg_user_slots_low);
		STATUS(msg_user_slots_high);
		STATUS(msg_user_hub_limit_low);
		STATUS(msg_user_hub_limit_high);
		STATUS(msg_proto_no_common_hash);
		STATUS(msg_proto_obsolete_adc0);
	}
#undef STATUS
	return "Unknown";
}

const char* hub_get_status_message_log(struct hub_info* hub, enum status_message msg)
{
#define STATUS(MSG) case status_ ## MSG : return #MSG
	switch (msg)
	{
		STATUS(msg_hub_full);
		STATUS(msg_hub_disabled);
		STATUS(msg_hub_registered_users_only);
		STATUS(msg_inf_error_nick_missing);
		STATUS(msg_inf_error_nick_multiple);
		STATUS(msg_inf_error_nick_invalid);
		STATUS(msg_inf_error_nick_long);
		STATUS(msg_inf_error_nick_short);
		STATUS(msg_inf_error_nick_spaces);
		STATUS(msg_inf_error_nick_bad_chars);
		STATUS(msg_inf_error_nick_not_utf8);
		STATUS(msg_inf_error_nick_taken);
		STATUS(msg_inf_error_nick_restricted);
		STATUS(msg_inf_error_cid_invalid);
		STATUS(msg_inf_error_cid_missing);
		STATUS(msg_inf_error_cid_taken);
		STATUS(msg_inf_error_pid_missing);
		STATUS(msg_inf_error_pid_invalid);
		STATUS(msg_ban_permanently);
		STATUS(msg_ban_temporarily);
		STATUS(msg_auth_invalid_password);
		STATUS(msg_auth_user_not_found);
		STATUS(msg_error_no_memory);
		STATUS(msg_user_share_size_low);
		STATUS(msg_user_share_size_high);
		STATUS(msg_user_slots_low);
		STATUS(msg_user_slots_high);
		STATUS(msg_user_hub_limit_low);
		STATUS(msg_user_hub_limit_high);
		STATUS(msg_proto_no_common_hash);
		STATUS(msg_proto_obsolete_adc0);
	}
#undef STATUS
	return "unknown";
}


size_t hub_get_user_count(struct hub_info* hub)
{
	return hub->users->count;
}

size_t hub_get_max_user_count(struct hub_info* hub)
{
	return hub->config->max_users;
}

uint64_t hub_get_shared_size(struct hub_info* hub)
{
	return hub->users->shared_size;
}

uint64_t hub_get_shared_files(struct hub_info* hub)
{
	return hub->users->shared_files;
}

uint64_t hub_get_min_share(struct hub_info* hub)
{
	uint64_t size = hub->config->limit_min_share;
	size *= (1024 * 1024);
	return size;
}

uint64_t hub_get_max_share(struct hub_info* hub)
{
        uint64_t size = hub->config->limit_max_share;
        size *= (1024 * 1024);
        return size;
}

size_t hub_get_min_slots(struct hub_info* hub)
{
	return hub->config->limit_min_slots;
}

size_t hub_get_max_slots(struct hub_info* hub)
{
	return hub->config->limit_max_slots;
}

size_t hub_get_max_hubs_total(struct hub_info* hub)
{
	return hub->config->limit_max_hubs;
}

size_t hub_get_min_hubs_total(struct hub_info* hub)
{
	return hub->config->limit_min_hubs;
}

size_t hub_get_max_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_user;
}

size_t hub_get_min_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_user;
}

size_t hub_get_max_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_reg;
}

size_t hub_get_min_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_reg;
}

size_t hub_get_max_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_op;
}

size_t hub_get_min_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_op;
}

void hub_schedule_destroy_user(struct hub_info* hub, struct hub_user* user)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_USER_DESTROY;
	post.ptr = user;
	event_queue_post(hub->queue, &post);

	if (user->id.sid)
	{
		sid_free(hub->users->sids, user->id.sid);
	}
}

void hub_disconnect_all(struct hub_info* hub)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_HUB_SHUTDOWN;
	post.ptr = 0;
	event_queue_post(hub->queue, &post);
}

void hub_event_loop(struct hub_info* hub)
{
	do
	{
		net_backend_process();
		event_queue_process(hub->queue);
	}
	while (hub->status == hub_status_running || hub->status == hub_status_disabled);


	if (hub->status == hub_status_shutdown)
	{
		LOG_DEBUG("Removing all users...");
		event_queue_process(hub->queue);
		event_queue_process(hub->queue);
		hub_disconnect_all(hub);
		event_queue_process(hub->queue);
		hub->status = hub_status_stopped;
	}
}


void hub_disconnect_user(struct hub_info* hub, struct hub_user* user, int reason)
{
	struct event_data post;
	int need_notify = 0;

	/* is user already being disconnected ? */
	if (user_is_disconnecting(user))
	{
		return;
	}

	/* stop reading from user */
	net_shutdown_r(net_con_get_sd(user->connection));
	net_con_close(user->connection);
	user->connection = 0;

	LOG_TRACE("hub_disconnect_user(), user=%p, reason=%d, state=%d", user, reason, user->state);

	need_notify = user_is_logged_in(user) && hub->status == hub_status_running;
	user->quit_reason = reason;
	user_set_state(user, state_cleanup);

	if (need_notify)
	{
		memset(&post, 0, sizeof(post));
		post.id     = UHUB_EVENT_USER_QUIT;
		post.ptr    = user;
		event_queue_post(hub->queue, &post);
	}
	else
	{
		hub_schedule_destroy_user(hub, user);
	}
}

/**
 * Handle TCP validation messages for HBRI (Hybrid Bridge).
 * This command is used by clients to validate they have the IP addresses
 * they claim to have, enabling IPv4/IPv6 cross-connectivity.
 *
 * @param hub Hub instance
 * @param u User sending the command
 * @param cmd TCP command message
 * @return 0 on success, -1 on error
 */
int hub_handle_tcp(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* token = NULL;
	struct hbri_pending_entry* entry = NULL;
	struct node* node = NULL;
	struct hub_user* validated_user = NULL;
	char* claimed_ip = NULL;
	const char* actual_ip = NULL;
	int ip_version_to_validate = 0;
	int validation_success = 0;
	struct adc_message* sta_cmd = NULL;
	int validation_is_ipv6 = 0;
	int connection_is_ipv6 = 0;

	/* Extract token from command */
	token = adc_msg_get_named_argument(cmd, "TO");
	if (!token)
	{
		LOG_INFO("HBRI: TCP validation command received from %s (%s)",
			sid_to_string(u->id.sid), user_get_address(u));
		/* Send error status */
		hub_send_status(hub, u, status_msg_hbri_validation_failed, status_level_error);
		return -1;
	}

	/* Look for token in pending validations */
	entry = NULL;
	node = list_get_first_node(hub->hbri_pending);
	while (node)
	{
		entry = (struct hbri_pending_entry*) list_get(node);
		if (entry && strcmp(entry->token, token) == 0)
		{
			break;
		}
		node = node->next;
	}

	if (!entry)
	{
		LOG_INFO("HBRI: Unknown validation token %s from %s (%s)",
			token, sid_to_string(u->id.sid), user_get_address(u));
		hub_free(token);
		/* Send error status */
		hub_send_status(hub, u, status_msg_hbri_validation_failed, status_level_error);
		return -1;
	}

	validated_user = entry->user;
	ip_version_to_validate = entry->ip_version;

	LOG_INFO("HBRI: Validation token %s matched for user %s (nick: %s, validating IPv%d)",
		token, sid_to_string(validated_user->id.sid),
		validated_user->id.nick, ip_version_to_validate);

	/* Check if validation is being performed over the correct IP protocol */
	validation_is_ipv6 = (ip_version_to_validate == 6);
	connection_is_ipv6 = user_is_ipv6(u);

	if (validation_is_ipv6 == connection_is_ipv6)
	{
		LOG_INFO("HBRI: Validation request was received over the wrong IP protocol (validating IPv%d over %s connection)",
			ip_version_to_validate, connection_is_ipv6 ? "IPv6" : "IPv4");
		hub_free(token);
		/* Send error status */
		hub_send_status(hub, u, status_msg_hbri_validation_failed, status_level_error);
		/* Disconnect validation connection */
		hub_disconnect_user(hub, u, quit_hbri);
		/* Allow main user to continue joining */
		hub_fail_hbri_validation(hub, validated_user);
		return -1;
	}

	/* Get the claimed IP address from the user's info */
	if (ip_version_to_validate == 4)
	{
		claimed_ip = adc_msg_get_named_argument(validated_user->info, ADC_INF_FLAG_IPV4_ADDR);
	}
	else if (ip_version_to_validate == 6)
	{
		claimed_ip = adc_msg_get_named_argument(validated_user->info, ADC_INF_FLAG_IPV6_ADDR);
	}

	/* Get actual IP from validation connection */
	actual_ip = user_get_address(u);

	/* Parse and validate IP addresses properly */
	if (claimed_ip && actual_ip)
	{
		/* Parse claimed IP */
		struct ip_addr_encap claimed_addr;
		struct ip_addr_encap actual_addr;
		int claimed_valid = 0;
		int actual_valid = 0;

		/* Parse claimed IP address */
		if (ip_version_to_validate == 4)
		{
			claimed_valid = (net_string_to_address(AF_INET, claimed_ip, &claimed_addr.internal_ip_data.in) > 0);
			if (claimed_valid) claimed_addr.af = AF_INET;
		}
		else if (ip_version_to_validate == 6)
		{
			claimed_valid = (net_string_to_address(AF_INET6, claimed_ip, &claimed_addr.internal_ip_data.in6) > 0);
			if (claimed_valid) claimed_addr.af = AF_INET6;
		}

		/* Parse actual IP address */
		if (connection_is_ipv6)
		{
			actual_valid = (net_string_to_address(AF_INET6, actual_ip, &actual_addr.internal_ip_data.in6) > 0);
			if (actual_valid) actual_addr.af = AF_INET6;
		}
		else
		{
			actual_valid = (net_string_to_address(AF_INET, actual_ip, &actual_addr.internal_ip_data.in) > 0);
			if (actual_valid) actual_addr.af = AF_INET;
		}

		/* Check if IP addresses are valid and match */
		if (claimed_valid && actual_valid && ip_compare(&claimed_addr, &actual_addr) == 0)
		{
			LOG_INFO("HBRI: IP validation successful for user %s (nick: %s, IPv%d: %s)",
				sid_to_string(validated_user->id.sid), validated_user->id.nick,
				ip_version_to_validate, actual_ip);
			validation_success = 1;

			/* Update user's validated IP status */
			if (ip_version_to_validate == 4)
			{
				user_flag_set(validated_user, flag_ipv4_validated);
			}
			else if (ip_version_to_validate == 6)
			{
				user_flag_set(validated_user, flag_ipv6_validated);
			}
		}
		else
		{
			if (!claimed_valid)
			{
				LOG_INFO("HBRI: Invalid claimed IP address %s for user %s (nick: %s)",
					claimed_ip, sid_to_string(validated_user->id.sid), validated_user->id.nick);
			}
			else if (!actual_valid)
			{
				LOG_INFO("HBRI: Invalid actual IP address %s from validation connection",
					actual_ip);
			}
			else
			{
				LOG_INFO("HBRI: IP validation failed for user %s (nick: %s, claimed IPv%d: %s, actual: %s)",
					sid_to_string(validated_user->id.sid), validated_user->id.nick,
					ip_version_to_validate, claimed_ip, actual_ip);
			}
			validation_success = 0;
		}
	}
	else
	{
		LOG_INFO("HBRI: Missing IP address for validation (claimed: %s, actual: %s)",
			claimed_ip ? claimed_ip : "none", actual_ip ? actual_ip : "none");
		validation_success = 0;
	}

	/* Send status to validation connection */
	if (validation_success)
	{
		/* Send success status (code 000) */
		sta_cmd = adc_msg_construct(ADC_CMD_ISTA, 64);
		adc_msg_add_argument(sta_cmd, "000");
		adc_msg_add_argument_string(sta_cmd, "Validation successful");
		route_to_user(hub, u, sta_cmd);
		adc_msg_free(sta_cmd);
	}
	else
	{
		/* Send IP mismatch error */
		hub_send_status(hub, u, status_msg_hbri_ip_mismatch, status_level_error);
	}

	/* Disconnect validation connection */
	hub_disconnect_user(hub, u, quit_hbri);

	/* Remove from pending list */
	if (node)
	{
		list_remove_node(hub->hbri_pending, node);
		hub_free(entry);
	}

	/* Clear user's HBRI validating flag */
	user_flag_unset(validated_user, flag_hbri_validating);

	/* Handle validation result */
	if (validation_success && validated_user->state == state_hbri_waiting)
	{
		/* If validation was successful and user was waiting, continue login */
		LOG_INFO("HBRI: Continuing login for user %s (nick: %s) after successful validation",
			sid_to_string(validated_user->id.sid), validated_user->id.nick);
		hub_continue_login_after_hbri(hub, validated_user);
	}
	else if (!validation_success && validated_user->state == state_hbri_waiting)
	{
		/* If validation failed and user was waiting, allow them to continue without the validated IP */
		LOG_INFO("HBRI: Validation failed for user %s (nick: %s), allowing to continue without validated IP",
			sid_to_string(validated_user->id.sid), validated_user->id.nick);
		hub_fail_hbri_validation(hub, validated_user);
	}

	if (claimed_ip)
		hub_free(claimed_ip);
	hub_free(token);

	return 0;
}

/**
 * Handle failed HBRI validation by allowing user to continue without validated IP.
 * This is called when HBRI validation fails or times out.
 *
 * @param hub Hub instance
 * @param user User who failed HBRI validation
 */
void hub_fail_hbri_validation(struct hub_info* hub, struct hub_user* user)
{
	if (!user || user->state != state_hbri_waiting)
		return;

	LOG_INFO("HBRI: Allowing user %s (nick: %s) to continue without validated IP",
		sid_to_string(user->id.sid), user->id.nick);

	/* Clear HBRI validating flag */
	user_flag_unset(user, flag_hbri_validating);

	/* Strip the IP address that requires validation from the stored INF */
	if (user->info)
	{
		if (user->hbri_ip_version == 4)
		{
			adc_msg_remove_named_argument(user->info, ADC_INF_FLAG_IPV4_ADDR);
			adc_msg_remove_named_argument(user->info, ADC_INF_FLAG_IPV4_UDP_PORT);
		}
		else if (user->hbri_ip_version == 6)
		{
			adc_msg_remove_named_argument(user->info, ADC_INF_FLAG_IPV6_ADDR);
			adc_msg_remove_named_argument(user->info, ADC_INF_FLAG_IPV6_UDP_PORT);
		}
	}

	/* Continue with normal login process */
	user_set_state(user, state_identify);

	/* Process the stored INF message */
	if (user->info)
	{
		/* Create a copy of the INF message to avoid use-after-free issues */
		struct adc_message* cmd_copy = adc_msg_copy(user->info);
		if (cmd_copy)
		{
			int ret = hub_handle_info_login(hub, user, cmd_copy);
			adc_msg_free(cmd_copy);
			if (ret < 0)
			{
				LOG_ERROR("HBRI: Login failed for user %s (nick: %s) after HBRI failure, error code: %d",
					sid_to_string(user->id.sid), user->id.nick, ret);
				on_login_failure(hub, user, ret);
			}
		}
		else
		{
			LOG_ERROR("HBRI: Failed to copy INF message for user %s (nick: %s)",
				sid_to_string(user->id.sid), user->id.nick);
			on_login_failure(hub, user, status_msg_inf_error_cid_invalid);
		}
	}
}

/**
 * Initiate HBRI validation for a user.
 * This is called when a user needs to validate they have an IP address
 * of a different version than their connection (e.g., IPv6 user claiming IPv4).
 *
 * @param hub Hub instance
 * @param user User to validate
 * @param ip_version IP version to validate (4 or 6)
 * @return 0 on success, -1 on error
 */
int hub_initiate_hbri_validation(struct hub_info* hub, struct hub_user* user, uint8_t ip_version)
{
	struct hbri_pending_entry* entry = NULL;
	struct adc_message* cmd = NULL;
	char token[9];

	/* Generate validation token */
	if (!generate_hbri_token(token, sizeof(token)))
	{
		LOG_ERROR("HBRI: Failed to generate token for user %s (nick: %s)",
			sid_to_string(user->id.sid), user->id.nick);
		return -1;
	}

	/* Create pending entry */
	entry = hub_malloc_zero(sizeof(struct hbri_pending_entry));
	if (!entry)
	{
		LOG_ERROR("HBRI: Failed to allocate memory for pending entry");
		return -1;
	}

	strncpy(entry->token, token, sizeof(entry->token) - 1);
	entry->token[sizeof(entry->token) - 1] = '\0';
	entry->user = user;
	entry->expires = time(NULL) + 30; /* 30 second timeout */
	entry->ip_version = ip_version;

	/* Add to pending list */
	list_append(hub->hbri_pending, entry);

	/* Set user flag */
	user_flag_set(user, flag_hbri_validating);

	/* Strip feature cast supports for the IP version being validated */
	user_strip_feature_cast_for_hbri(user, ip_version);

	/* Store token in user struct for reference */
	strncpy(user->hbri_token, token, sizeof(user->hbri_token) - 1);
	user->hbri_token[sizeof(user->hbri_token) - 1] = '\0';
	user->hbri_timeout = entry->expires;
	user->hbri_ip_version = ip_version;

	/* Create TCP command to send to user */
	cmd = adc_msg_construct(ADC_CMD_TCP, 64);
	if (!cmd)
	{
		LOG_ERROR("HBRI: Failed to create TCP command for user %s", sid_to_string(user->id.sid));
		list_remove(hub->hbri_pending, entry);
		hub_free(entry);
		return -1;
	}

	/* Add token parameter */
	adc_msg_add_named_argument_string(cmd, "TO", token);

	/* Add IP version specific parameters */
	if (ip_version == 4)
	{
		adc_msg_add_named_argument_string(cmd, "I4", "0.0.0.0");
		adc_msg_add_named_argument_string(cmd, "U4", "0");
	}
	else if (ip_version == 6)
	{
		adc_msg_add_named_argument_string(cmd, "I6", "::");
		adc_msg_add_named_argument_string(cmd, "U6", "0");
	}

	/* Send the TCP command to the user */
	LOG_INFO("HBRI: Initiated validation for user %s (nick: %s), token=%s, ipv=%d, connection_ip=%s",
		sid_to_string(user->id.sid), user->id.nick, token, ip_version, user_get_address(user));

	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
	return 0;
}

/**
 * Continue user login after successful HBRI validation.
 * @param hub Hub instance
 * @param user User who passed HBRI validation
 * @return 0 on success, -1 on error
 */
int hub_continue_login_after_hbri(struct hub_info* hub, struct hub_user* user)
{
	int ret;

	if (!user || !user->info || user->state != state_hbri_waiting)
	{
		LOG_ERROR("HBRI: Cannot continue login for invalid user state (user=%p, info=%p, state=%d)",
			user, user ? user->info : NULL, user ? user->state : -1);
		return -1;
	}

	LOG_INFO("HBRI: Continuing login process for user %s (nick: %s)",
		sid_to_string(user->id.sid), user->id.nick);

	/* Process the stored INF message */
	/* Create a copy of the INF message to avoid use-after-free issues */
	struct adc_message* cmd_copy = adc_msg_copy(user->info);
	if (!cmd_copy)
	{
		LOG_ERROR("HBRI: Failed to copy INF message for user %s (nick: %s)",
			sid_to_string(user->id.sid), user->id.nick);
		on_login_failure(hub, user, status_msg_inf_error_cid_invalid);
		return -1;
	}

	ret = hub_handle_info_login(hub, user, cmd_copy);
	adc_msg_free(cmd_copy);
	if (ret < 0)
	{
		LOG_ERROR("HBRI: Login failed for user %s (nick: %s) after validation, error code: %d",
			sid_to_string(user->id.sid), user->id.nick, ret);
		on_login_failure(hub, user, ret);
		return -1;
	}
	else
	{
		/* Post a message, the user has joined */
		struct event_data post;
		memset(&post, 0, sizeof(post));
		post.id    = UHUB_EVENT_USER_JOIN;
		post.ptr   = user;
		post.flags = ret; /* 0 - all OK, 1 - need authentication */
		event_queue_post(hub->queue, &post);
		LOG_INFO("HBRI: User %s (nick: %s) login continued successfully, flags: %d",
			sid_to_string(user->id.sid), user->id.nick, ret);
		return 0;
	}
}

/**
 * HBRI timeout callback function.
 * Checks for expired HBRI validations and cleans them up.
 */
static void hub_hbri_timeout_callback(struct timeout_evt* t)
{
	struct hub_info* hub = (struct hub_info*) t->ptr;
	struct hbri_pending_entry* entry = NULL;
	struct node* node = NULL;
	struct node* next_node = NULL;
	time_t now = time(NULL);

	if (!hub || !hub->hbri_pending)
		return;

	/* Check for expired validations */
	node = list_get_first_node(hub->hbri_pending);
	while (node)
	{
		next_node = node->next;
		entry = (struct hbri_pending_entry*) list_get(node);

		if (entry && entry->expires < now)
		{
			LOG_INFO("HBRI: Validation token %s expired for user %s (nick: %s)",
				entry->token, sid_to_string(entry->user->id.sid),
				entry->user->id.nick);

			/* Clear user's HBRI validation flag */
			user_flag_unset(entry->user, flag_hbri_validating);

			/* If user was waiting for HBRI validation, allow them to continue */
			if (entry->user->state == state_hbri_waiting)
			{
				LOG_INFO("HBRI: HBRI timeout for user %s (nick: %s), allowing to continue without validated IP",
					sid_to_string(entry->user->id.sid), entry->user->id.nick);
				/* Send HBRI timeout status to user */
				hub_send_status(hub, entry->user, status_msg_hbri_timeout, status_level_error);
				/* Allow user to continue without validated IP */
				hub_fail_hbri_validation(hub, entry->user);
			}

			/* Remove from list */
			list_remove_node(hub->hbri_pending, node);
			hub_free(entry);
		}

		node = next_node;
	}

	/* Reschedule for next check */
	timeout_queue_reschedule(net_backend_get_timeout_queue(), hub->hbri_timeout, 1);
}
