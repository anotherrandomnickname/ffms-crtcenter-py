from sanic import Sanic
from sanic.log import logger
from sanic.response import json
import json as encoder
from sanic.request import RequestParameters
from sanic.response import text
from sanic import response
from sanic_cors import CORS, cross_origin
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import db
import datetime
import requests

cred = credentials.Certificate('./serviceAccountKey.json')
firebase = firebase_admin.initialize_app(cred, {'databaseURL': 'https://fairy-db978.firebaseio.com'})
PATH_SALT = 'FVa3vxsIjScs'
UNIQUE_IDENTIFY = 'SnHuLP5he6dnw36k'

app = Sanic()

@app.route("/")
async def test(request):
    return json({"hello": "world"})



@app.route('/register', methods=['PUT', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def register(request):
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    email = decoded['email']
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')
    name = email.split('@', 1)[0].title()

    logger.info("DECODED TOKEN: %s" % id_token)

    """ if ctrf_token_body != ctrf_token_cookies:
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403
        )
 """
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        auth.set_custom_user_claims(uid, {
            'accessLevel': 2,
            'specificAccess': 0,
            'admin': False,
        })
        try:
            URL = "http://localhost:8010/register/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            data_params = {
                'accessLevel': 2,
                'specificAccess': 0,
                'firebase_uid': uid,
                'name': name,
            }
            r = requests.put(url=URL, json=data_params)
            data = r.json()
            response = json(data, status=r.status_code)
            return response
        except:
            return json({'message': 'failed to register'}, status=401)
    except auth.AuthError:
        return json({'message': 'failed to register'}, status=401)


@app.route('/login', methods=['POST', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def post_login(request):
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token_body != ctrf_token_cookies:
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403
        )
    
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        logger.info('DECODED TOKEN: %s' % decoded_token)
        if 'accessLevel' in decoded_token:
            access_level = decoded_token['accessLevel']
        else:
            access_level = 2
        expires = datetime.timedelta(days=5)
        session_cookie = auth.create_session_cookie(id_token, expires_in=expires)
        try:
            URL = "http://localhost:8010/sessionlogin/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY 
            logger.info("URL: %s", URL)
            r = requests.get(url=URL)
            data = r.json()
            dataname = r.content
            response = json({
                'accessLevel': access_level,
                'user': data
                })
            response.cookies['session'] = session_cookie
            response.cookies['session']['httponly'] = True
            return response
        except: 
            return json({'message': 'failed to login'}, status=404)
    except auth.AuthError:
        return json({'message': 'failed to create session cookie '}, status=401)


    logger.info('UID %s' % uid)
    return json(
        {"OK": 200},
    )

@app.route('/profile?<idtoken>?<ctrftoken>?<pk>', methods=['GET', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def get_user_profile(request, idtoken, ctrftoken, pk):
    query_string = request.query_string.split('&')
    id_token = query_string[0].split('=', 1)[-1]
    ctrf_token_params = query_string[1].split('=', 1)[-1]
    pk_params = query_string[2].split('=', 1)[-1]
    ctrf_token_cookies = request.cookies.get('ctrf')

    logger.info('PK: %s' % pk_params)
    """ logger.info('TOKEN: %s' % id_token)
    logger.info('CTRF TOKEN: %s' %ctrf_token_params)
    logger.info('CTRF TOKEN COOKIES: %s' %ctrf_token_cookies) """

    if ctrf_token_params != ctrf_token_cookies:
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try:
            URL = 'http://localhost:8010/own_user_profile/' + PATH_SALT
            data_params = {
                'uid': uid
            }
            r = requests.get(url=URL, json=data_params)
            data = r.json()
            response = json(data, status=r.status_code)
            return response
        except: 
            return json({'message': 'failed to resolve user'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)



    return json({'message': 'SYUCCESS'}, status=200)



@app.route('/createpost', methods=['PUT', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def create_post(request):
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token_body != ctrf_token_cookies:
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )
    
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        forum_id = decoded['fid']
        topic_id = decoded['tid']
        post = decoded['post']
        try:
            URL = "http://localhost:8010/createpost/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            logger.info('PUT URL: %s' % URL)
            data_params = {
                'tid': decoded['tid'],
                'fid': decoded['fid'],
                'post': decoded['post']
            }
            r = requests.put(url=URL, json=data_params)
            data = r.json()
            response = json(data, status=r.status_code)
            return response
        except: 
            return json({'message': 'failed to create post'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)


@app.route('/deletepost?<idtoken>?<ctrftoken>?<postpk>?<topicpk>?<forumpk>', methods=['DELETE', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def delete_post(request, idtoken, ctrftoken, postpk, topicpk, forumpk):
    """ req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded('idToken')
    ctrf_token_body = decoded('ctrfToken')
    ctrf_token_cookies = request.cookies.get('ctrf') """

    """ logger.info('POSTPK: %s' % postpk)
    logger.info('TOPICPK: %s' % topicpk)
    logger.info('FORUMPK: %s' % forumpk) """
    """ logger.info('CTRFTOKEN: {}'.format(ctrf_token)) """

    query_string = request.query_string.split('&')
    id_token = query_string[0].split('=', 1)[-1]
    ctrf_token_params = query_string[1].split('=', 1)[-1]
    post_pk = query_string[2].split('=', 1)[-1]
    topic_pk = query_string[3].split('=', 1)[-1]
    forum_pk = query_string[4].split('=', 1)[-1]
    ctrf_token_cookies = request.cookies.get('ctrf')

    logger.info('POSTPK: %s' % post_pk)
    logger.info('TOPICPK: %s' % topic_pk)
    logger.info('FORUMPK: %s' % forum_pk)
    logger.info('CTRF TOKEN: %s' %ctrf_token_params)
    logger.info('CTRF TOKEN COOKIES: %s' %ctrf_token_cookies)


    if ctrf_token_params != ctrf_token_cookies:
        return json(
            {message: 'CTRF ATTACK!'},
            status=403
        )
    try: 
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try:
            URL = "http://localhost:8010/deletepost/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            data_params = {
                'postpk': post_pk,
                'topicpk': topic_pk,
                'forumpk': forum_pk,
            }
            r = requests.post(url=URL, json=data_params)
            data = r.json()
            response = json(data, status=r.status_code)
            return response
        except:
            return json({'message': 'failed to delete post'}, status=403)
    except Auth.AuthError:
        return json({'message': 'invalid user'}, status=401)
    
    return json({'message': 'SUCCESS!'})


@app.route('/updatepost', methods=['POST', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
async def update_post(request):
    logger.info("HELLO")
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token_body != ctrf_token_cookies:
        logger.info("POLNY PIZDETC")
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try: 
            URL =  "http://localhost:8010/updatepost/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            logger.info('POST URL: %s' % URL)
            data_params = {
                'post': decoded['post'],
                'postpk': decoded['ppk'],
                'firebase_uid': uid
            }
            r = requests.post(url=URL, json=data_params)
            logger.info('RESPONSE STATUS: %s' % r.status_code)
            data = r.json()
            response = json(data, status=r.status_code)
            return response
        except:
            return json({'message': 'post update failed'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)


@app.route('/createtheme', methods=['PUT', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
def create_theme(request):
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token_body != ctrf_token_cookies:
        logger.info("POLNY PIZDETC")
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try:
            URL =  "http://localhost:8010/createtheme/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            data_params = {
                'body': decoded['body'],
                'name': decoded['name'],
                'description': decoded['description'],
                'userpk': decoded['userpk'],
                'fid': decoded['fid']
            }
            r = requests.put(url=URL, json=data_params)
            data = r.json()
            response = {
                'status': 'SUCCESS!'
            }
            logger.info('RESPONSE STATUS: %s' % r.status_code)
            response = json(response, status=r.status_code)
            return response
        except: 
            return json({'message': 'create theme failed'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)

@app.route('/deletetheme?<forumid>?<topicid>?<idtoken>?<ctrftoken>', methods=['DELETE', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
def delete_theme(request, forumid, topicid, idtoken, ctrftoken):
    query_string = request.query_string.split('&')
    forum_id = query_string[0].split('=', 1)[-1]
    topic_id = query_string[1].split('=', 1)[-1]
    id_token = query_string[2].split('=', 1)[-1]
    ctrf_token = query_string[3].split('=', 1)[-1]
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token != ctrf_token_cookies:
        logger.info("POLNY PIZDETC")
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try:
            URL =  "http://localhost:8010/deletetheme/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            data_params = {
                'fid': forum_id,
                'tid': topic_id,
            }
            r = requests.post(url=URL, json=data_params)
            data = r.json()
            response = {
                'status': 'SUCCESS!'
            }
            logger.info('RESPONSE STATUS: %s' % r.status_code)
            response = json(response, status=r.status_code)
            return response
        except: 
            return json({'message': 'delete theme failed'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)


@app.route('/updatetheme', methods=['POST', 'OPTIONS'])
@cross_origin(app, supports_credentials=True, automatic_options=True, origins='http://localhost:8080')
def update_theme(request):
    req_json = request.body.decode('utf-8')
    decoded = encoder.loads(req_json)
    id_token = decoded['idToken']
    ctrf_token_body = decoded['ctrfToken']
    ctrf_token_cookies = request.cookies.get('ctrf')

    if ctrf_token_body != ctrf_token_cookies:
        logger.info("POLNY PIZDETC")
        return json(
            {'message': 'CTRF ATTACK!'},
            status = 403 )
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        try:
            URL =  "http://localhost:8010/updatetheme/" + PATH_SALT + '/' + uid + '/' + UNIQUE_IDENTIFY
            data_params = {
                'body': decoded['body'],
                'name': decoded['name'],
                'description': decoded['description'],
                'pk': decoded['pk']
            }
            r = requests.post(url=URL, json=data_params)
            data = r.json()
            response = {
                'status': 'SUCCESS!'
            }
            logger.info('RESPONSE STATUS: %s' % r.status_code)
            response = json(response, status=r.status_code)
            return response
        except: 
            return json({'message': 'update theme failed'}, status=403)
    except auth.AuthError:
        return json({'message': 'invalid user'}, status=401)

def listen_changes(event):
    logger.info('CHANGES!: %s' % event.data)

@app.route('/user_presence', methods=['GET', 'OPTIONS'])
@cross_origin(app, origins='http://localhost:8080')
async def get_presented_users(request):
    ref = db.reference('/presence/')
    data = ref.get()
    logger.info('DATA: %s' % data)
    return json({'data': data}, status = 200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3111)