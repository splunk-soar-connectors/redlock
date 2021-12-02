# File: redlock_connector.py
#
# Copyright (c) 2018 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from redlock_consts import *
import json
import requests
import datetime
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RedlockConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RedlockConnector, self).__init__()

        self._state = None
        self._token = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, json=None, method="get"):

        config = self.get_config()

        resp_json = None

        if headers is None:
            headers = dict()

        if self._token:
            headers['x-redlock-auth'] = self._token

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = '{}{}'.format(REDLOCK_BASE_URL, endpoint)

        try:
            r = request_func(
                url,
                json=json,
                headers=headers,
                verify=config.get('verify_server_cert', False),
                params=params
            )
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _login(self, action_result):
        config = self.get_config()
        username = config['username']
        password = config['password']
        body = {
            'username': username,
            'password': password,
        }
        ret_val, response = self._make_rest_call('/login', action_result, json=body, method="post")
        if phantom.is_fail(ret_val):
            return ret_val

        self._token = response['token']
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Logging in...")
        if phantom.is_fail(self._login(action_result)):
            self.save_progress("Failed to authenticate with RedLock API")
            return action_result.get_status()

        self.save_progress("Verifying authorization credentials...")
        ret_val, response = self._make_rest_call('/check', action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity failed")
            self.save_progress("API returned an error")
            return ret_val

        self.save_progress("Test Connectivity passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_ms_sinc_epoch(self, days_back=0):
        dt = datetime.datetime.now() - datetime.timedelta(days=int(days_back))
        return int(dt.strftime('%s')) * 1000

    def _create_containers(self, action_result, alert_list):

        # The api only returns severity (low, medium, high), so
        # let's just map the severity to these
        sensitivity_map = {
            'low': 'green',
            'high': 'red'
        }

        for alert in alert_list:
            container = dict()
            artifact = dict()

            container['artifacts'] = [artifact]

            policy = alert['policy']
            resource = alert['resource']

            container['name'] = '{}: {}'.format(policy['name'], resource['name'])
            container['severity'] = policy['severity']
            container['sensitivity'] = sensitivity_map.get(policy['severity'], 'amber')
            container['source_data_identifier'] = alert['id']
            if alert['status'] in ('dismissed', 'resolved'):
                container['status'] = 'closed'

            artifact['name'] = '{} Alert'.format(policy['name'])
            artifact['cef'] = alert

            ret_val, response, cid = self.save_container(container)
            self.debug_print("Save container returned: {}, id: {}".format(response, cid))

    def _handle_on_poll(self, param):
        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))
        max_containers = param.get('container_count', 0)

        self.save_progress("Logging in...")
        if phantom.is_fail(self._login(action_result)):
            self.save_progress("Failed to authenticate with RedLock API")
            return action_result.get_status()

        end_time = self._get_ms_sinc_epoch()
        start_time = self._state.get('start_time')
        if not start_time:
            # first (scheduled) ingestion
            ingest_days_back = config.get('ingest_days_back', 0)
            if ingest_days_back:
                start_time = self._get_ms_sinc_epoch(ingest_days_back)
            else:
                start_time = 0

        body = {
            'timeRange': {
                'type': 'absolute',
                'value': {
                    'startTime': start_time,
                    'endTime': end_time,
                },
            }
        }

        params = {
            'detailed': 'true'
        }

        ret_val, response = self._make_rest_call(
            '/alert',
            action_result,
            json=body,
            params=params,
            method='post'
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to retrieve events")
            return ret_val

        if max_containers:
            response = response[-max_containers:]

        self._create_containers(action_result, response)

        if not self.is_poll_now():
            self._state['start_time'] = end_time

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RedlockConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
