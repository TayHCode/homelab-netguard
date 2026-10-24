"""Private, fixed-origin ntfy delivery. Only fixed text and bounded counts leave."""
import json
import os
import re
import urllib.error
import urllib.request


TOPIC_ENV = 'NETGUARD_NTFY_TOPIC_FILE'
EVENTS = frozenset({
    'new_device', 'new_ports', 'auth_failed', 'dns_suffix',
    'dns_long_label', 'dns_entropy', 'baseline_missing', 'baseline_mismatch',
    'baseline_scope_review',
} | {'coverage_' + component for component in (
    'lan_discovery', 'host_discovery', 'host_offline', 'tcp_scan',
    'log_read', 'log_backlog', 'dns_parse', 'model_triage', 'state_read',
    'baseline_read', 'baseline_approval', 'configuration_or_io', 'overlapping_run',
)})
MAX_LINES = 8
MAX_LINE = 200


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(lines=(), *, mode='alert', delayed=False):
    if TOPIC_ENV not in os.environ:
        return {'status': 'disabled'}
    try:
        with open(os.environ[TOPIC_ENV], 'rb') as source:
            raw = source.read(66)
        topic = raw.decode('ascii').removesuffix('\n')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', topic):
            raise ValueError()
    except (OSError, UnicodeError, ValueError):
        return {'status': 'failed', 'error_type': 'TopicFileError'}
    if mode == 'test':
        title, body = 'Netguard test', 'Netguard test notification. Alert-only monitoring.'
    elif mode == 'failure':
        title, body = 'Netguard monitoring incomplete', 'Netguard scanner failed to complete; monitoring incomplete. Review the local scanner.'
    elif mode in ('alert', 'digest'):
        lines = [str(line)[:MAX_LINE] for line in lines]
        shown = lines[:MAX_LINES]
        if len(lines) > MAX_LINES:
            shown.append('+' + str(len(lines) - MAX_LINES) + ' more in the local report.')
        if mode == 'alert':
            title = 'Netguard: new on your network'
            if delayed:
                shown.insert(0, 'Delayed from an earlier delivery failure.')
            shown.append('Alert only; nothing was changed.')
        else:
            title = 'Netguard morning digest'
            shown = shown or ['Nothing new since the last digest.']
        body = '\n'.join(shown)
    else:
        return {'status': 'failed', 'error_type': 'NotificationModeError'}
    request = urllib.request.Request('https://ntfy.sh/' + topic, data=body.encode('ascii', 'replace'),
                                     headers={'Title': title, 'Priority': '3' if mode in ('test', 'digest') else '4',
                                              'Content-Type': 'text/plain; charset=utf-8'}, method='POST')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=8) as response:
            if not 200 <= response.status < 300:
                return {'status': 'failed', 'error_type': 'HTTPError'}
            raw = response.read(8193)
        # HTTP acceptance is success even if optional receipt metadata is malformed.
        result = {'status': 'accepted'}
        if len(raw) <= 8192:
            try:
                message_id = json.loads(raw).get('id')
                if isinstance(message_id, str) and re.fullmatch(r'[A-Za-z0-9]{12}', message_id) and topic not in message_id and message_id not in topic:
                    result['id'] = message_id
            except (ValueError, AttributeError):
                pass
        return result
    except urllib.error.HTTPError as error:
        try:
            error.close()
        except Exception:
            pass
        return {'status': 'failed', 'error_type': 'HTTPError'}
    except Exception:
        return {'status': 'failed', 'error_type': 'TransportError'}
