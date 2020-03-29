from __future__ import absolute_import
from __future__ import unicode_literals

import datetime
import json
import logging
import sys
import time

from six import integer_types
from six import text_type as unicode

if len(integer_types) == 1:
    long = integer_types[0]
import flask
from google.cloud import ndb
import memorystore

sys.path.insert(0, 'includes')
from webapp_class_wrapper import wrap_webapp_class
from datavalidation import DataValidation
from GCP_return_codes import FunctionReturnCodes as RC
from error_handling import CR as RDK
from GCP_datastore_logging import LoggingFuctions
from p1_global_settings import GlobalSettings as GSB
from p1_services import Services as Services
from p1_services import TaskArguments
from p1_services import TaskNames
from p1_datastores import Datastores as DsP1
from task_queue_functions import CreateTransactionFunctions as CTF
from datastore_functions import DatastoreFunctions as DSF


class OauthVerify(object):
    def VerifyToken(self):
        task_id = "web-requests:OauthVerify:VerifyToken"
        return_msg = 'web-requests:OauthVerify:VerifyToken: '
        debug_data = []
        authenticated = False

        call_result = self.VerifyTokenProcessRequest()
        authenticated = call_result['authenticated']
        debug_data.append(call_result)

        if call_result['success'] != RC.success:
            params = {}
            for key in self.request.arguments():
                params[key] = self.request.get(key, None)

            log_class = LoggingFuctions()
            log_class.logError(call_result['success'], task_id, params, None, None, call_result['return_msg'],
                               call_result['debug_data'], None)
            if call_result['success'] == RC.failed_retry:
                self.response.set_status(500)
            elif call_result['success'] == RC.input_validation_failed:
                self.response.set_status(400)
            elif call_result['success'] == RC.ACL_check_failed:
                self.response.set_status(401)

        if authenticated == True:
            return {'success': call_result['success'], 'return_msg': return_msg, 'debug_data': debug_data,
                    'authenticated': authenticated}
        else:
            self.response.set_status(401)
            return {'success': call_result['success'], 'return_msg': return_msg, 'debug_data': debug_data,
                    'authenticated': authenticated}

    def VerifyTokenProcessRequest(self):
        return_msg = 'web-requests:OauthVerify:VerifyTokenProcessRequest '
        debug_data = []
        authenticated = False
        ## validate input
        client_token_id = unicode(self.request.get('p1s3_token', ''))
        user_email = unicode(self.request.get('p1s3_firebase_email', ''))

        call_result = self.checkValues([[client_token_id, True, unicode, "len>10", "len<"],
                                        [user_email, True, unicode, "email_address"]
                                        ])
        debug_data.append(call_result)
        if call_result['success'] != True:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data,
                    'authenticated': authenticated}

        ##</end> validate input

        ## try to pull cached data
        current_time = time.mktime(datetime.datetime.now().timetuple())
        mem_client = memorystore.Client()
        try:
            verified_token_id = mem_client.get(user_email + "-token_id")
            verified_token_expiration = long(mem_client.get(user_email + "-token_expiration"))
        except:
            verified_token_id = None
            verified_token_expiration = 0

        logging.info("verified_token_id:" + unicode(verified_token_id) + "| client_token_id:" + unicode(
            client_token_id) + '|verified_token_expiration:' + unicode(
            verified_token_expiration) + '|current_time:' + unicode(current_time))
        tokens_match = False
        if verified_token_id != None and verified_token_id == client_token_id:
            tokens_match = True

        if verified_token_id != None and verified_token_id == client_token_id and verified_token_expiration > current_time:
            authenticated = True
            return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data,
                    'authenticated': authenticated}
        ##</end> try to pull cached data

        ## use the external libraray to auth
        logging.info("loading VM_oauth_external")
        from WM_oauth_external import OauthExternalVerify
        external_oauth = OauthExternalVerify()
        call_result = external_oauth.VerifyTokenID(client_token_id, user_email)
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += "oauth external call failed"
            return {'success': call_result['success'], 'return_msg': return_msg, 'debug_data': debug_data,
                    'authenticated': authenticated}

        authenticated = call_result['authenticated']
        ##</end> use the external libraray to auth

        return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data,
                'authenticated': authenticated}


ndb_client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):
    def middleware(environ, start_response):
        with ndb_client.context():
            return wsgi_app(environ, start_response)

    return middleware


app = flask.Flask(__name__)
app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)


class CommonPostHandler(DataValidation, OauthVerify):
    def options(self):
        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

    def post(self, *args, **kwargs):
        debug_data = []
        task_id = 'web-requests:CommonPostHandler:post'

        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

        call_result = self.VerifyToken()
        debug_data.append(call_result)
        if call_result['authenticated'] != RC.success:
            self.response.set_status(401)
            return

        call_result = self.process_request(*args, **kwargs)
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            params = {}
            for key in self.request.arguments():
                params[key] = self.request.get(key, None)
            LF = LoggingFuctions()
            LF.logError(
                call_result[RDK.success], task_id, params, None, None, call_result[RDK.return_msg], call_result
            )

        self.create_response(call_result)

    def create_response(self, call_result):
        if call_result['success'] == RC.success:
            self.create_success_response(call_result)
        else:
            self.create_error_response(call_result)

    def create_success_response(self, call_result):
        self.response.set_status(204)

    def create_error_response(self, call_result):
        if call_result['success'] == RC.failed_retry:
            self.response.set_status(500)
        elif call_result['success'] == RC.input_validation_failed:
            self.response.set_status(400)
        elif call_result['success'] == RC.ACL_check_failed:
            self.response.set_status(401)

        self.response.out.write(call_result['return_msg'])


@app.route(Services.web_request.create_need.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.web_request.create_need.name)
class CreateNeed(CommonPostHandler):
    def process_request(self):
        task_id = 'web-requests:CreateNeed:process_request'
        debug_data = []
        return_msg = task_id + ": "
        user_uid = "1"

        # input validation
        need_name = unicode(self.request.get(TaskArguments.s3t1_name, ""))
        requirements = unicode(self.request.get(TaskArguments.s3t1_requirements, "")) or None

        call_result = self.ruleCheck([
            [need_name, DsP1.needs._rule_need_name],
            [requirements, DsP1.needs._rule_requirements],
        ])

        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data}
        # </end> input validation

        ## create transaction to create user in datastore
        pma = {
            TaskArguments.s1t1_name: need_name,
        }
        if requirements:
            pma[TaskArguments.s1t1_requirements] = requirements

        task_sequence = [{
            'name': TaskNames.s1t1,
            'PMA': pma,
        }]

        try:
            task_sequence = unicode(json.JSONEncoder().encode(task_sequence))
        except Exception as e:
            return_msg += "JSON encoding of task_queue failed with exception:%s" % e
            return {'success': False, 'return_msg': return_msg, 'debug_data': debug_data}

        task_functions = CTF()
        call_result = task_functions.createTransaction(GSB.project_id, user_uid, task_id,
                                                       task_sequence)
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += 'failed to add task queue function'
            return {'success': call_result['success'], 'debug_data': debug_data, 'return_msg': return_msg}
        ##</end> create transaction to create user in datastore

        return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data}


@app.route(Services.web_request.assign_need_to_needer.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.web_request.assign_need_to_needer.name)
class AssignNeedToNeeder(CommonPostHandler):
    def process_request(self):
        task_id = 'web-requests:AssignNeedToNeeder:process_request'
        debug_data = []
        return_msg = task_id + ": "
        transaction_user_uid = "1"

        # input validation
        need_uid = unicode(self.request.get(TaskArguments.s3t2_need_uid, ""))
        needer_uid = unicode(self.request.get(TaskArguments.s3t2_needer_uid, ""))
        user_uid = unicode(self.request.get(TaskArguments.s3t2_user_uid, ""))
        special_requests = unicode(self.request.get(TaskArguments.s3t2_special_requests, "")) or None

        call_result = self.ruleCheck([
            [need_uid, DsP1.needer_needs_joins._rule_need_uid],
            [needer_uid, GSB.post_data_rules.required_name],
            [user_uid, GSB.post_data_rules.required_name],
            [special_requests, DsP1.needer_needs_joins._rule_special_requests],
        ])

        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data}

        try:
            existings_keys = [
                ndb.Key(DsP1.needer._get_kind(), long(needer_uid)),
                ndb.Key(DsP1.needs._get_kind(), long(need_uid)),
                ndb.Key(DsP1.users._get_kind(), long(user_uid)),
            ]
        except Exception as exc:
            return_msg += str(exc)
            return {
                'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data,
            }

        for existing_key in existings_keys:
            call_result = DSF.kget(existing_key)
            debug_data.append(call_result)
            if call_result['success'] != RC.success:
                return_msg += "Datastore access failed"
                return {
                    'success': RC.datastore_failure, 'return_msg': return_msg, 'debug_data': debug_data,
                }
            if not call_result['get_result']:
                return_msg += "{} not found".format(existing_key.kind())
                return {
                    'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data,
                }
        # </end> input validation

        pma = {
            TaskArguments.s2t4_need_uid: need_uid,
            TaskArguments.s2t4_needer_uid: needer_uid,
            TaskArguments.s2t4_user_uid: user_uid,
        }
        if special_requests:
            pma[TaskArguments.s2t4_special_requests] = special_requests

        ## create transaction to create user in datastore
        task_sequence = [{
            'name': TaskNames.s2t4,
            'PMA': pma,
        }]

        try:
            task_sequence = unicode(json.JSONEncoder().encode(task_sequence))
        except Exception as e:
            return_msg += "JSON encoding of task_queue failed with exception:%s" % e
            return {'success': False, 'return_msg': return_msg, 'debug_data': debug_data}

        task_functions = CTF()
        call_result = task_functions.createTransaction(
            GSB.project_id, transaction_user_uid, task_id, task_sequence
        )
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += 'failed to add task queue function'
            return {'success': call_result['success'], 'debug_data': debug_data, 'return_msg': return_msg}
        ##</end> create transaction to create user in datastore

        return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data}


@app.route(Services.web_request.create_user.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.web_request.create_user.name)
class CreateUser(CommonPostHandler):
    def process_request(self):
        task_id = 'web-requests:CreateUser:process_request'
        debug_data = []
        return_msg = task_id + ": "
        user_uid = "1"

        # input validation
        first_name = unicode(self.request.get(TaskArguments.s3t3_first_name, ""))
        last_name = unicode(self.request.get(TaskArguments.s3t3_last_name, ""))
        phone = unicode(self.request.get(TaskArguments.s3t3_phone_number, "")) or None

        call_result = self.ruleCheck([
            [first_name, GSB.post_data_rules.required_name],
            [last_name, GSB.post_data_rules.required_name],
            [phone, DsP1.users._rule_phone_1]
        ])

        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data}
        # </end> input validation

        pma = {
            TaskArguments.s1t4_first_name: first_name,
            TaskArguments.s1t4_last_name: last_name,
        }
        if phone:
            pma[TaskArguments.s1t4_phone_number] = phone

        ## create transaction to create user in datastore
        task_sequence = [{
            'name': TaskNames.s1t4,
            'PMA': pma,
        }]

        try:
            task_sequence = unicode(json.JSONEncoder().encode(task_sequence))
        except Exception as e:
            return_msg += "JSON encoding of task_queue failed with exception:%s" % e
            return {'success': False, 'return_msg': return_msg, 'debug_data': debug_data}

        task_functions = CTF()
        call_result = task_functions.createTransaction(
            GSB.project_id, user_uid, task_id, task_sequence
        )
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += 'failed to add task queue function'
            return {'success': call_result['success'], 'debug_data': debug_data, 'return_msg': return_msg}
        ##</end> create transaction to create user in datastore

        return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data}


if __name__ == "__main__":
    app.run(debug=True)
