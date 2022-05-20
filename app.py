


'''
Created on 

Course work: 

@author: tactlabs

Source:
    https://stackoverflow.com/questions/14888799/disable-console-messages-in-flask-server
'''


#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask import make_response
from flask.helpers import flash
from flask_cors import CORS
import os.path
import os
import json
import re
import requests
from datetime import datetime
import random
import urllib.request
from urllib.parse import urlparse
from functools import wraps
from authlib.integrations.flask_client import OAuth
# from decouple import config
from werkzeug.utils import secure_filename
import logging

import pprint
# Local import
import fpr_business
from zenv import *
from fpr_consumer import FPRClient
import fpr_s3_util
import fpr_util
# from dotenv import load_dotenv
import tlogger

# https://bit.ly/3y9Q7aV
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#

app = Flask(__name__)

app.secret_key = 'enjaamiTale$eFennelda$S' 

oauth = OAuth(app)

cors            = CORS(app)

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))


# PORT            = 8083
SESSION_ID_KEY  = "sid"

UPLOAD_FOLDER       = 'static/uploads/'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# app.config['SECRET_KEY']            = os.getenv("SECRET_KEY")
app.config["GOOGLE_CLIENT_ID"]      = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"]  = os.getenv("GOOGLE_CLIENT_SECRET")
app.config["PORT"]                  = os.getenv("FPR_UI_JINJA_PORT")
app.config["API_BASE2"]             = os.getenv("API_BASE2")

logging.basicConfig(
    filename    = "fe_frontend.log", 
    level       = logging.INFO
)

google = oauth.register(
    name = 'google',
    client_id = app.config["GOOGLE_CLIENT_ID"],
    client_secret = app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs = {'scope': 'openid email profile'},
)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_domain_from_url(url):
    
    parsed_uri = urlparse(url)
    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

    return result

def get_base_url():

    return get_domain_from_url(request.base_url)

def requires_session(f):
  
    @wraps(f)
    def decorated(*args, **kwargs):

        # check apikey in args
        if SESSION_ID_KEY not in session:

            # data = {
            #     'apiresult' : 'Session Not Available',
            #     'apimessage': 1011
            # }

            # return jsonify(data)
            
            session['redirect_url'] = request.url
            return redirect(url_for('page_login_get'))

        # verify user_session
        user_session = session.get(SESSION_ID_KEY)

        return f(*args, **kwargs)

    return decorated

def is_session_valid():

    if(SESSION_ID_KEY in session):
        return True

    return False

def get_sid():

    return session[SESSION_ID_KEY]

def get_userid():

    return session["user_id"]



#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#

@app.route("/ping", methods = ['GET'])
def ping():

    # app.logger.info('Chaaya does not like BTS')
    tlogger.info('Opps Chaaya likes BTS')
    
    result_dict = {
        'ping' : 'done'
    }

    # return response_utils.success_response(result_dict)
    return jsonify(result_dict)

@app.route('/domain', methods=['GET'])
def api_get_domain():

    result = {
        'base_url' : get_base_url()
    }
    return jsonify(result)

@app.route('/', methods=['GET', 'POST'])
def page_index():
    logged_in = is_session_valid()
    tlogger.info("logged_in", logged_in)
    return render_template(
        'index.html', logged_in = logged_in
    )

# @app.route("/api/login", methods=['POST'])
@app.route('/login', methods=['GET'])
def page_login_get():

    # check session available; if yes, redirect
    

    if(is_session_valid()):

        user_id = get_userid()
        resp = make_response(redirect(url_for('page_feature_get')))
        resp.set_cookie('user_id', str(user_id))

        la_config = fpr_business.get_la_sites(get_userid())
        if la_config['result']['config_list']:
            resp.set_cookie('sites', json.dumps({"sites":la_config['result']['config_list']}))
        return resp

    return render_template(
        'login.html'
    )


@app.route('/signup', methods=['POST'])
def page_signup_post():

    # username    = request.values.get('user_name')
    email       = request.values.get('email')
    password    = request.values.get('password')
    user_role   = 2
    
    result_json = fpr_business.post_signup_user(email, email, password, user_role)

    # return jsonify(result_json)
    logged_in = is_session_valid()

    if result_json["error_code"] != 0:
        return  render_template(
            'error.html', 
            result = result_json, logged_in = logged_in
        )

    session[SESSION_ID_KEY] = result_json['result']['sid']
    session["user_id"]      = result_json['result']['user_id']
    result                  = result_json['result']

    user_id = get_userid()
    resp = make_response(redirect(url_for('page_feature_get')))
    resp.set_cookie('user_id', str(user_id))
    return resp
    # return redirect(url_for('page_feature_get'))


@app.route('/signup', methods=['GET'])
def page_signup_get():

    return render_template(
        'sign_up.html'
    )

# @app.route("/api/login", methods=['POST'])
@app.route('/login', methods=['POST'])
def page_login_post():

    username = request.values.get('email')
    password = request.values.get('password')

    result_json = fpr_business.login_user(username, password)

    logged_in = is_session_valid()

    if result_json["error_code"] != 0:
        return  render_template(
            'error.html', 
            result = result_json,logged_in = logged_in
        )

    # assume login is successful
    session[SESSION_ID_KEY] = result_json['result']['sid']
    session["user_id"]      = result_json['result']['user_id']
    result                  = result_json['result']
    
    user_id = get_userid()
    try:
        # session['redirect_url'] = request.url
        
        resp = make_response(redirect(session["redirect_url"]))
    except:

        resp = make_response(redirect(url_for('page_feature_get')))
    resp.set_cookie('user_id', str(user_id))
    la_config = fpr_business.get_la_sites(get_userid())
    if la_config['result']['config_list']:
        resp.set_cookie('sites', json.dumps({"sites":la_config['result']['config_list']}))
    return resp
    # return redirect(url_for('page_feature_get'))

@app.route('/login/google')
def google_login():

    google = oauth.create_client('google')

    fpr_env = fpr_util.get_fpr_env()

    if(fpr_env == 'PROD' or fpr_env == 'DEV' or fpr_env == 'QA'):
        redirect_uri = "https://featurepreneur.com" + "/login/google/authorize"
    else:
        redirect_uri = url_for('google_authorize', _external=True)

    # enable this only for house
    # redirect_uri = url_for('google_authorize', _external=True)

    # redirect_uri = "https://featurepreneur.com" + "/login/google/authorize"

    # redirect_uri = "https://localhost:8083" + "/login/google/authorize"

    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize', methods=["GET","POST"])
def google_authorize(): 
    
        google = oauth.create_client('google')
        token = google.authorize_access_token()
        resp = google.get('userinfo').json()

        google_id   = resp['id'] 
        email       = resp['email']

        result_json = fpr_business.post_google_login(google_id, email)

        session[SESSION_ID_KEY] = result_json['result']['sid']
        session["user_id"]      = result_json['result']['user_id']
        result                  = result_json['result']

        user_id = get_userid()
        resp = make_response(redirect(url_for('page_feature_get')))
        resp.set_cookie('user_id', str(user_id))

        la_config = fpr_business.get_la_sites(get_userid())
        if la_config['result']['config_list']:
            resp.set_cookie('sites', json.dumps({"sites":la_config['result']['config_list']}))
        return resp       
        # return redirect(url_for("page_feature_get"))

@app.route('/coins', methods=['GET'])
@requires_session
def page_get_user_coins():

    userid  = get_userid()
    s_id    = get_sid()
    result_json   = fpr_business.get_user_coins(userid, s_id)
    
    if(result_json["error_code"]!=0):
        return render_template('coins.html',data=0)

    return render_template(
        'coins.html', data=result_json
    )

@app.route('/coins-history', methods=['GET'])
@requires_session
def page_get_coins_history():

    userid  = get_userid()
    s_id    = get_sid()
    result_json = fpr_business.get_user_coins_history(userid, s_id)

    result = result_json['result']['tact_coins_history']

    return render_template(
        'coins-history.html', data=result
    )

@app.route('/logout', methods=['GET'])
def page_logout_get():

    del session[SESSION_ID_KEY]

    resp = make_response(redirect(url_for('page_index')))

    resp.set_cookie('user_id', '', expires=0)
    resp.set_cookie('sites', '', expires=0)

    return resp

'''
    http://127.0.0.1:8083/api/test
'''
@app.route('/api/test', methods=['GET'])
def page_apitest():

    result =  {
        'apibase' : fpr_business.get_apibase()
    }

    return jsonify(result)

@app.route('/template', methods=['GET'])
def page_template():

    return render_template(
        'template.html'
    )

@app.route('/my-features', methods=["GET"])
def page_feature_get():

    result_json = fpr_business.get_user_features(get_userid())
    result_json_1 = fpr_business.get_all_users_features()
    
    result_1 = result_json['result']['features']
    result_2 = result_json_1['result']['features']

    return render_template(
        'features.html', data = result_1, data1 = result_2
    )
  
def get_page(request):

    page = request.values.get("page")

    if(not page):
        page = "1"

    page = int(page) 

    return page
 
@app.route('/features', methods=["GET"])
def page_public_feature_get():

    '''
        page = get_page(request)

    result_data = akon.get_all_volunteers(page)
    
    if("result" in result_data):
        result = result_data['result']
        result['current_url_part'] = 'volunteers'
    else:
        result = {}
        result['current_url_part'] = 'volunteers'
        result["current_page"] = 1

    '''
    page = get_page(request)

    logged_in = is_session_valid()

    result_json = fpr_business.get_all_features(page)

    if("result" in result_json):

        result = result_json['result']
        result['current_url_part'] = 'features'
    else:
        result = {}
        result['current_url_part'] = 'features'
        result["current_page"] = 1

    return render_template(
        'public-features.html', result = result, logged_in = logged_in
    )

@app.route('/features/<feature_url>', methods=["GET", "POST"])
def page_public_feature_details_get(feature_url):

    user_id             = None
    session_available   = False

    if(is_session_valid()):
        user_id = get_userid()
        session_available = True
        result_json = fpr_business.get_feature_details(feature_url, user_id)
    else:
        result_json = fpr_business.get_feature_details_not_logged(feature_url)

    result          = result_json['result']['feature_details']

    api_key         = os.getenv("API_KEY")
    api_base        = os.getenv("API_BASE2")
    user_ip_url     = os.getenv("USER_IP_URL")

    ip_json         = requests.get(user_ip_url)
    result_ip_json  = ip_json.content.decode()
    result_ip_json  = json.loads(result_ip_json)

    user_ip = request.headers.get('X-Forwarded-For')

    # return jsonify(result)
    
    return render_template(
        'public-features-details.html',
        donations           = result_json["result"]["donations"],
        user_id             = user_id, 
        feature_user_id     = result["user_id"], 
        result              = result, 
        feature_url         = feature_url, 
        api_key             = api_key, 
        api_base            = api_base, 
        user_ip             = result_ip_json, 
        user_credits        = result_json['result']['user_credits'], 
        session_available   = session_available
    )

'''
#/like/{{feature_url}} 

@app.route('/like/<feature_url>', methods=["GET", "POST"])
def page_add_like(feature_url):

    result_json = fpr_business.add_like_feature(feature_url)

    result = result_json['result']['feature_info']

    return redirect(url_for('page_public_feature_details_get', feature_url=feature_url))
'''

@app.route('/publish-feature', methods=["GET"])
@requires_session
def page_publish_get():

    return render_template(
        'publish_feature.html'
    )

@app.route('/publish-feature', methods=["POST"])
@requires_session
def page_publish_feature_post():

    # return request.files

    # file upload
    file_upload_result_code, filepath, uploaded_image_name, uploaded_image_name_list = upload_feature_image_local()

    tlogger.info("file_upload_result_code : ", file_upload_result_code)
    tlogger.info("uploaded_image_name : ", uploaded_image_name_list)

    data = {
        "title"                     : request.values.get('feature-title'),
        "short_summary"             : request.values.get('short_summary'),
        "loom_link"                 : request.values.get('loom-link'),
        "medium_link"               : request.values.get('medium-link'),
        "youtube_link"              : request.values.get('youtube-link'),
        "feature_req_link"          : request.values.get('feature-req-link'),
        "feature_screenshot_link"   : uploaded_image_name_list,
        "user_id"                   : get_userid()
    }

    if(file_upload_result_code == 0):
        data['feature_thumbnail_image_name'] = uploaded_image_name
    else:
        data['feature_thumbnail_image_name'] = '-'

    result_json = fpr_business.publish_new_feature(data, get_sid())

    return redirect(
        url_for('page_feature_get')
    )

def upload_feature_image_local():

    if request.method == 'POST':

        # check if the post request has the file part
        if 'files[]' not in request.files:        
            return 1002, "No File Avaialbale", None

        files = request.files.getlist('files[]')

        filepath_list = []
        uploaded_image_name_list = []

        for file in files:
            
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                return 1003, "No File Avaialbale", None

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                filepath_list.append(filepath)
                # upload to s3
                result_code, uploaded_image_name = fpr_s3_util.upload_feature_image(filepath, get_userid(), 2001)
                tlogger.info('uploaded_image_name : ', uploaded_image_name)
                fpr_s3_base = get_usercourse_s3_base_path()

                image_name = fpr_s3_base + uploaded_image_name
                uploaded_image_name_list.append(image_name)

                # delete_uploaded_file(filepath)

        return 0, filepath, uploaded_image_name, uploaded_image_name_list

    return 1004, "File Uplaod Unknown Error", None

def get_usercourse_s3_base_path():

    FPR_USERFEATURE_UPLOAD_S3           = "tactindia"
    FPR_USERFEATURE_UPLOAD_BASE_FOLDER  = '/featurepreneur/userfeatures/'
    fpr_s3_base = os.environ.get('FPR_USERFEATURE_S3_BASE') + FPR_USERFEATURE_UPLOAD_BASE_FOLDER
    
    return fpr_s3_base

#/api/get/feature/by/url/<feature_url>
'''
@app.route('/features/<feature_url>', methods=["GET", "POST"])
def page_feature_details_get(feature_url):

    result_json = fpr_business.get_feature_details(feature_url)    
    result = result_json['result']['feature_details']

    # return jsonify(result)
    
    return render_template(
        'feature_details.html',result=result
    )
'''
@app.route('/courses', methods = ["GET"])
@requires_session
def page_show_courses_get():

    userid  = get_userid()
    s_id    = get_sid()
    result_dict = fpr_business.get_user_courses(userid, s_id)

    # return jsonify(result_dict)

    return render_template('courses.html', result = result_dict['result'])

@app.route('/all/courses', methods = ["GET"])
@requires_session
def page_show_all_courses_get():
    s_id    = get_sid()
    result_dict = fpr_business.get_all_courses_ttc( s_id)

    # return jsonify(result_dict)
    return render_template('all_courses.html', result = result_dict['result'])

#/subscribe/all
@app.route('/subscribe/all', methods = ["GET"])
@requires_session
def page_subscribe_all_courses_post():

    s_id    = get_sid()
    userid  = get_userid()

    result_dict = fpr_business.post_subscribe_all(userid, s_id)

    # return jsonify(result_dict)
    return render_template('all_courses.html', result = result_dict['result'])


@app.route('/course/<course_id>', methods = ["GET"])
@requires_session
def page_show_videos_get(course_id):

    s_id    = get_sid()
    result_dict = fpr_business.get_course_videos(course_id, s_id)

    return render_template('course.html', result = result_dict['result'])


@app.route('/video/<coursevideo_id>')
@requires_session
def page_show_video_details_get(coursevideo_id):
  
    s_id    = get_sid()
    result_dict = fpr_business.get_course_video_details(coursevideo_id, s_id)

    if(result_dict):
        course_id = result_dict['result']['course_video_details']['course_id']
        course_videos_dict = fpr_business.get_course_videos(course_id, s_id)

    
    course_video_list = course_videos_dict['result']['videos']
    
    return render_template('video.html', result = result_dict['result'], course_videos = course_video_list)

@app.route('/gifts', methods = ["GET"])
@requires_session
def page_user_gifts_get():

    userid  = get_userid()
    s_id    = get_sid()
    result_dict = fpr_business.get_user_gifts(userid, s_id)
    return render_template('gifts.html', result = result_dict['result'])

@app.route('/gifts/<gift_id>', methods = ["GET"])
@requires_session
def page_gift_details_get(gift_id):

    user_id  = get_userid()
    s_id    = get_sid()

    result_dict         = fpr_business.get_gift_details(gift_id, s_id)
    result_dict_user    = fpr_business.get_user_gifts(user_id, s_id) 

      
    return render_template('gifts_details.html', result = result_dict['result'], result_user = result_dict_user['result']) 

@app.route('/user/details', methods = ["GET"])
@requires_session
def page_user_details_get():

    user_id  = get_userid()
    s_id     = get_sid()

    result_dict_user = fpr_business.get_user_details(user_id, s_id)

    if(result_dict_user["error_code"]!=0):
       return render_template('fill_user_details.html', user_result= None)
    
    return render_template("fill_user_details.html", user_result=result_dict_user) 

@app.route('/testimonial', methods = ["GET"])
def page_testimonial_get():

    return render_template('testimonial.html') 

@app.route('/add/my/shipping/address', methods=["GET","POST"])
def page_add_user_details_post():

    data = {
        "user_id"                     : get_userid(),
        "full_name"                   : request.values.get('user_full_name'),
        "contact_no"                  : request.values.get('contact_no'),
        "house_no"                    : request.values.get('house_no'),
        "street_name"                 : request.values.get('street_name'),
        "area_name"                   : request.values.get('area_name'),
        "city_name"                   : request.values.get('city_name'),
        "state"                       : request.values.get('state'),
        "landmark"                    : request.values.get('landmark'),
        "pin_code"                    : request.values.get('pin_code'),
        
    }

    
    result_json = fpr_business.add_user_details(data)


    return redirect(
        url_for('page_user_details_get')
    )



@app.route('/gifts/ordered/<gift_id>', methods = ["GET"])
@requires_session
def page_gift_ordered_get(gift_id):

    user_id  = get_userid()
    s_id    = get_sid()
  
    result_dict         = fpr_business.get_gift_details(gift_id, s_id) 
    
    result_dict_user    = fpr_business.get_user_gifts(user_id, s_id)

    return render_template('gifts_details_ordering.html',result = result_dict['result'], result_user = result_dict_user['result'])


@app.route('/check/out/page/<gift_id>', methods = ["GET","POST"])
@requires_session
def page_check_out_get(gift_id):

    user_id  = get_userid()

    s_id    = get_sid()

    result_dict = fpr_business.get_gift_details(gift_id, s_id) 

    result_dict_user = fpr_business.get_user_details(user_id, s_id) 

    return render_template('check_out_page.html', gift_result = result_dict, user_result = result_dict_user)


@app.route('/order/confirm/<gift_id>', methods = ["GET"])
@requires_session
def page_confirm_order_get(gift_id):

    s_id    = get_sid()

    user_id  = get_userid() 

    result_dict = fpr_business.get_confirm_order(gift_id, user_id, s_id) 

    if result_dict["error_code"] != 0:

        return render_template('receipt_page.html', result = result_dict)

    return render_template('receipt_page.html')


@app.route('/all/orders', methods = ["GET"])
@requires_session
def page_all_ordered_gifts_get():

    s_id                = get_sid()

    user_id             = get_userid() 

    result_dict_gifts   = fpr_business.get_user_gifts(user_id, s_id)

    result_dict         = fpr_business.get_all_order(user_id, s_id) 

    return render_template('ordered_gifts_page.html', result = result_dict_gifts['result'])

@app.route('/file/upload', methods=['GET'])
def page_upload_file_get():
    
    return render_template('file_upload.html')

def delete_uploaded_file(filepath):

    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    
    return False

@app.route('/upload_file', methods=['POST'])
def page_upload_file_post():
    
    # check if the post request has the file part
    if 'file' not in request.files:        
        result = {
            'result' : 0,    
            'error' : 'file not available',
        }
        # return render_template('result.html', result=result)
        return jsonify(result)
    
    file = request.files['file']
    
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':        
        result = {
            'result' : 0,    
            'error' : 'file not available',
        }
        
        # return render_template('result.html', result=result)
        return jsonify(result)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # upload to s3
        result_code, uploaded_image_name = fpr_s3_util.upload_feature_image(filepath, 1001, 2001)

        delete_uploaded_file(filepath)

        result = {
            'result' : 1,
            'error' : '0',
            'image_location' : filepath,
            'uploaded_image_name' : uploaded_image_name
        }

        return jsonify(result)
        # return render_template('result.html', result = result, filepath = filepath)
    
    result = {
        'result' : 0,
        'error' : 102
    }

    return jsonify(result)
    # return content
    # return render_template('result.html', user=user)

@app.route('/video-check', methods=['GET'])
def video_page_2():

    return render_template('video2.html') 

@app.route('/learning-entry', methods=['GET'])
def page_learning_entries_get():

    

    return render_template('learning_entries.html')

@app.route('/learning-entry', methods=['POST'])
def page_learning_entries_post():

    return render_template('learning_entries.html')

@app.route('/privacy.html', methods=['GET'])
def page_privacy_policy():

    return render_template('privacy_policy.html')

@app.route('/toc.html', methods=['GET'])
def page_terms_conditions():

    return render_template('terms_and_conditions.html')

@app.route('/fun-with-python', methods=['GET'])
def fun_with_html():

    return render_template('wharton.html')

@app.route('/courses/ttc', methods = ["GET"])
@requires_session
def page_show_courses_ttc_get():
 
    user_id  = get_userid()
    s_id    = get_sid()
    result_dict = fpr_business.get_user_courses_ttc(user_id, s_id)
    
    # return jsonify(result_dict)

    return render_template('courses_ttc.html', result = result_dict['result'])


@app.route('/course/ttc/<course_id>', methods = ["GET"])
@requires_session
def page_show_videos_get_ttc(course_id):

    s_id    = get_sid()
    user_id  = get_userid()
    result_dict = fpr_business.get_all_course_details(course_id,user_id,s_id)
    result_dict2 = fpr_business.get_one_course_ttc_info(course_id, s_id)
    result = fpr_business.get_credits_info(user_id, s_id, course_id)

      
    user_credits = result["result"]["user_total_credit_coins"]

    subscription_cost = result["result"]["subscription_cost"]

    remaining_credits = result["result"]["remaining_credits"]

    # result_dict2 = fpr_business.check_validity(course_id,s_id,user_id)

    return render_template('course_ttc.html', result = result_dict['result']['videos'], course_id=course_id,validity=result_dict['result']['validity'], title= result_dict2["result"]["course"]["name"], description = result_dict2["result"]["course"]["description"],user_credits = user_credits, subscription_cost = subscription_cost, remaining_credits = remaining_credits )



@app.route('/course/ttc/leaderboard/<course_id>', methods = ["GET"])
@requires_session
def page_show_course_leaderboard_get_ttc(course_id):

    s_id    = get_sid()
    user_id  = get_userid()
    result_dict = fpr_business.get_course_weekly_leaderboard(course_id, s_id)

    # return str(result_dict)
    return render_template('course_leaderboard.html', result = result_dict['result']['score_list'], course_id=course_id, week_no = result_dict['result']['latest_week_no'], total_leaderboard = False)


@app.route('/course/ttc/leaderboard/all/<course_id>', methods = ["GET"])
@requires_session
def page_show_course_leaderboard_all_ttc(course_id):

    s_id    = get_sid()
    user_id  = get_userid()
    result_dict = fpr_business.get_course_all_leaderboard(course_id, s_id)

    # return str(result_dict)
    return render_template('course_leaderboard.html', result = result_dict['result']['leader_board_list'], course_id=course_id, week_no = result_dict['result']['latest_week_no'], total_leaderboard = True)



@app.route('/course/ttc/video/<course_id>/<ttc_id>', methods = ["GET"])
@requires_session
def page_show_videos_ttc_get(course_id,ttc_id):

    s_id    = get_sid()
    user_id  = get_userid()
    vimeo    = True
    
    # result_dict = fpr_business.get_all_course_details(course_id, s_id)
    result_dict = fpr_business.get_video_by_ttc(course_id, ttc_id, s_id)

    # (result_dict)
    result_dict1 = fpr_business.get_tips(result_dict["result"]["chapters"][0]["ttc_id"],user_id)

    string = result_dict['result']['chapters'][0]["video_link"]
    sub_string = "youtube"
    
    if(sub_string in string):
        vimeo = False

    # link = "https://www.youtube.com/embed/il_t1WVLNxk"

    return render_template('video_ttc.html',edit = False, vimeo = vimeo,

    side_nav =result_dict["result"]["course_details"], 
    result = result_dict['result']['chapters'][0], 
    results = result_dict1['result'], prev = result_dict['result']['previous_ttc_id'], 
    next = result_dict['result']['next_ttc_id'], 
    course_id = result_dict['result']['course_id'],
    
    )


@app.route('/course/ttc/video/<course_id>/<ttc_id>/edit', methods = ["GET"])
@requires_session
def page_show_videos_ttc_edit_tips(course_id,ttc_id):

    s_id    = get_sid()
    user_id  = get_userid()
    
    # result_dict = fpr_business.get_all_course_details(course_id, s_id)
    result_dict = fpr_business.get_video_by_ttc(course_id, ttc_id, s_id)

    result_dict1 = fpr_business.get_tips_to_edit(result_dict["result"]["chapters"][0]["ttc_id"],user_id)
    
    return render_template('video_ttc.html', edit = True,side_nav =result_dict["result"]["course_details"], result = result_dict['result']['chapters'][0], results = result_dict1["result"]["video"], prev = result_dict['result']['previous_ttc_id'], next = result_dict['result']['next_ttc_id'], course_id = result_dict['result']['course_id'])


@app.route('/course/ttc/video/tips/submit/<course_id>/<ttc_id>', methods = ["POST"])
@requires_session
def change_tips_mentor(course_id, ttc_id):

    data = {

            "ttc_id"            : ttc_id,
            "tips"              : request.form.get('tips')
    }

    result_dict = fpr_business.edit_tips_mentor_post(data)
    
    return redirect(f"/course/ttc/video/{course_id}/{ttc_id}")

@app.route('/api/like/feature/<feature_url>', methods = ["GET"])
# @requires_session
def api_feature_like(feature_url):

    result_dict = fpr_business.add_like_feature(feature_url)

    return result_dict

@app.route('/pass/change', methods = ["GET"])
@requires_session
def change_password():

    s_id = get_sid()
    user_id = get_userid()


    user_details = fpr_business.get_user_details(int(user_id), s_id)
    return render_template('password.html', user_details = user_details["result"]["user_details"])


@app.route('/pass/submit', methods = ["POST"])
@requires_session
def change_password_submit():
    userid  = get_userid()     
    password = request.values.get('password')
    password2 = request.values.get('password2')
    if password != password2:
        flash("Passwords don't match!")
        return redirect(url_for('change_password'))
    result_json = fpr_business.reset_password(userid, password)

    if result_json["result"]["pass_changed"] != True:
        return  render_template(
            'error.html', 
            result = result_json
        )

    return redirect(url_for('page_feature_get'))

@app.route("/new/user/details", methods=['GET'])
@requires_session
def new_user_details():

    return render_template('user_details.html')


@app.route('/subscribe/basic/courses', methods = ["GET"])
@requires_session
def subscribe_basic_courses_api():
    
    s_id    = get_sid()
    userid  = get_userid()     
    result_dict = fpr_business.subscribe_basic_courses(userid, s_id)

    if result_dict["error_code"] == 0:
    # return jsonify(result_dict)
        return redirect (url_for('page_show_courses_ttc_get'))
    return redirect(url_for('page_show_all_courses_get'))

@app.route('/ubuntu/quiz', methods = ['GET', 'POST'])
def ubuntu_quiz():
    return render_template("ubuntu.html" )

@app.route('/ubuntu/quiz/admin', methods = ['GET', 'POST'])
def ubuntu_quiz_admin():
    res=fpr_business.get_all_quiz_results()
    res= sorted(res["result"]["all_scores"], key = lambda i: (i['total_score']),reverse=True)
        
    return render_template("admin.html",res=res)

@app.route('/ubuntu/quiz/thankyou', methods = ['GET', 'POST'])
def thankyou():
    return render_template("thankyou.html")


@app.route('/api/check/user/like/<feature_url>', methods = ["GET"])
# @requires_session
def api_check_user_like(feature_url):
    user_id  = get_userid()
    if not user_id:
        return "False"
    result_dict = fpr_business.get_user_likes(user_id,feature_url)

    if (int(result_dict["result"]["likes_count"])<=5):
        return "True"
    else:
        return "False"


@app.route('/api/user/like/<feature_url>', methods = ["GET"])
@requires_session
def api_user_like(feature_url):
    userid  = get_userid()   

    result_dict = fpr_business.add_user_like_feature(userid,feature_url)

    return result_dict

@app.errorhandler(404)
def not_found(e):
    logged_in = is_session_valid()

    result ={
        "error_message" : "OOPS! You have entered wrong url"
    }
    
    return render_template("error.html", result =result, logged_in = logged_in)

def get_user_name_with_user_id(user_id):
    # userid  = get_userid()

    result_dict = fpr_business.get_user_name(user_id)

    return result_dict

@app.route('/recommendations', methods = ["GET"])
@requires_session
def api_any_reco():

    userid  = get_userid() 
    result_dict = fpr_business.get_user_recommendations(userid)

    username = get_user_name_with_user_id(userid)
    username = username["result"]["notes"].split('@')[0]

    if(result_dict["error_code"] == 0):

        return render_template("any-reco.html", result = result_dict["result"], result_1 = username)
    else:
        return render_template("any-reco.html", result = None, result_1 = username)


@app.route('/recommendation/certificate/<tact_reco_id>', methods = ["GET"])
@requires_session
def api_any_reco_id(tact_reco_id): 
    
    # userid  = get_userid() 

    result_dict = fpr_business.get_user_recommendations_id(tact_reco_id)

    s_id = get_sid() 
    user_id = result_dict["result"]["notes"][0]["issued_to"]

    user_details = fpr_business.get_user_details(int(user_id), s_id)['result']['user_details']

    username = get_user_name_with_user_id(int(user_id)) 

    username = username["result"]["notes"].split('@')[0] 
    result_dict["result"]["notes"][0]["skills"]=result_dict["result"]["notes"][0]["skills"].split(',')
    if(result_dict["error_code"] == 0):
        return render_template("any-reco-original.html", result = result_dict["result"], result_1 = username , user_details = user_details)
    
    else:
        return render_template("any-reco-original.html", result = None, result_1 = username, user_details = user_details)
 


@app.route('/sam', methods=['GET'])

def secret_admirer():
    logged_in = is_session_valid()

    return render_template(
        'sam_main.html', logged_in = logged_in
    )



@app.route('/sam', methods=['POST'])
def secret_admirer_search():
    search_term = request.form.get('search_term')
    data = {
        'search_word':str(search_term)
    }
    result_dict = fpr_business.sam_search(data)

    logged_in = is_session_valid()

    return render_template(
        'sam_main.html', logged_in = logged_in, result = result_dict
    )

@app.route('/sam/entry', methods=['GET'])

def secret_admirer_entry_search():
    logged_in = is_session_valid()

    return render_template(
        'sam_entry_search.html', logged_in = logged_in
    )
@app.route('/sam/entry', methods=['POST'])
def sam_entry_search():
    search_term = request.form.get('search_term')
    data = {
        'search_word':str(search_term)
    }
    result_dict = fpr_business.sam_search(data)

    logged_in = is_session_valid()

    return render_template(
        'sam_entry_search.html', logged_in = logged_in, result = result_dict
    )

    # userid  = get_userid()
    # s_id    = get_sid()
    # result_json   = fpr_business.get_user_coins(userid, s_id)


    # return render_template(
    #     'coins.html', data=result_json
    # )



@app.route('/sam/<user_name>', methods=['GET'])

def secret_admirer_profile(user_name):
    logged_in = is_session_valid()
    result_dict = fpr_business.sam_get_profile({"user_name":user_name})  

    return render_template(
        'sam_profile.html', logged_in = logged_in, profile_details = result_dict['result']['profile']
    )

@app.route('/sam/entry/<user_name>', methods=['GET'])

def secret_admirer_entry(user_name):
    logged_in = is_session_valid()



    return render_template(
        'sam_entry.html', logged_in = logged_in, user_name = user_name,
    )

@app.route('/sam/entry/submit', methods=['POST'])

def secret_admirer_entry_submit():
    logged_in = is_session_valid()
    data = {
            "admirer_name"         : request.form.get('entry-name'),
            "country"              : request.form.get('country'),
            "reason"               : request.form.get('reason'),
            "user_name"               : request.form.get('user_name'),
            "hint"             : request.form.get('hint')

    }


    result_dict = fpr_business.sam_entry_submit(data)


    return redirect(url_for('secret_admirer_search'))

@app.route('/sam/new_profile/<name>', methods=['GET'])

def secret_admirer_new_profile(name):
    logged_in = is_session_valid()

    return render_template(
        'sam_new_profile_entry.html', logged_in = logged_in, name = name,
    )

@app.route('/sam/new_profile', methods=['POST'])
def secret_admirer_new_profile_submit():
    logged_in = is_session_valid()

    data = {
            "admirer_name"          : request.form.get('entry-name'),
            "new_profile_name"      : request.form.get('new_profile_name'),
            "social_media_handle"   : request.form.get('socials_link'),
            "country"               : request.form.get('country'),
            "reason"                : request.form.get('reason'),
            "user_name"             : request.form.get('user_name'),
            "hint"             : request.form.get('hint')

    }

    result_dict = fpr_business.sam_new_profile_submit(data)

    return render_template(
        'sam_main.html', logged_in = logged_in,
    )


@app.route('/learning/partner', methods=['GET'])

def get_learning_partner():

    user_id  = get_userid()
    # logged_in = is_session_valid()

    result_dict = fpr_business.learning_partner(user_id)

    try:
        result = result_dict["result"]["result"][0]["partner_name"]
        bio = result_dict["result"]["result"][0]["bio"]
        location = result_dict["result"]["result"][0]["location"]

    except (IndexError , KeyError):
        result = None
        bio = None
        location = None 

    try:
        current_name = result_dict["result"]["current_username"]
    except:
        current_name = None

    return render_template(
        'learning_partner.html', partner_name = result, bio = bio, location = location, current_name = current_name , history = result_dict["result"]['history']
    )

@app.route('/username/format_and_redirect/<username_orig>', methods=['GET'])
def format_username(username_orig):
    
    username = username_orig.split('@')
    final_username = ""

    if len(username)==1:
        username = username_orig.split()
        for i in username:
            final_username= final_username+i
    else:
        final_username = username[0]
    
    final_username = final_username.lower()

    return (redirect(f'/volunteer/{final_username}'))



@app.route('/profile', methods=['GET'])
def volunteer_redirect():

    userid  = get_userid()
    s_id    = get_sid()
    result   = fpr_business.get_user_name(userid)
    # try:
    username_orig = result['result']['notes']
    username = username_orig.split('@')
    final_username = ""

    if len(username)==1:
        username = username_orig.split()
        for i in username:
            final_username= final_username+i
    else:
        final_username = username[0]

    final_username = final_username.lower()

    return (redirect(f'/volunteer/{final_username}'))
    # except:
        # result_coins   = fpr_business.get_user_coins(userid, s_id)

        # if(result_coins["error_code"]!=0):
        #     result_coins["tactcoins"] = 0
        #     result_coins["tact_credits"] = 0
        # else: 
        #     result_coins = result_coins["result"]


        # userid              = get_userid() 
        # result_certificates = fpr_business.get_user_recommendations(userid)


        # username = get_user_name_with_user_id()

        # username = username["result"]["notes"].split('@')[0]

        # user_details = fpr_business.get_user_details(userid, s_id)

        # if(result_certificates["error_code"] != 0):
        #     result_certificates = None
        # else: 
        #     result_certificates = result_certificates["result"]["notes"]
        # base_path = os.environ.get('FPR_USERFEATURE_S3_BASE')
        # default_dp_path = base_path + "/featurepreneur/userfeatures/default_profile_pic.jpg"




        # return render_template(
        #     'profile_page.html',user_details = user_details["result"]["user_details"], result_coins = result_coins, result_certificates = result_certificates, username = username, def_dp = default_dp_path
        # )


@app.route('/upload/profile/picture', methods=['GET'])
def profile_picture():

    return render_template("upload_profile_picture.html")


@app.route('/upload/profile/picture', methods=['POST'])
def profile_picture_upload():

    file_upload_result_code, filepath, uploaded_image_name, uploaded_image_name_list = upload_feature_image_local()

    data = {
            "user_id"                  : get_userid(),
            "profile_picture"          : uploaded_image_name
    }
    
    result_dict = fpr_business.submit_new_profile_pic(data)


    return render_template("upload_profile_picture.html")



#/update/bio
@app.route('/update/bio', methods=['GET'])
def update_bio_page():

    s_id    = get_sid()
    userid              = get_userid() 
    
    result_dict = fpr_business.get_user_details(userid, s_id)
    
    bio = result_dict["result"]["user_details"]["bio"]
    if bio == None:
        bio = ""
    username = result_dict["result"]["user_details"]["username"]
    role = result_dict["result"]["user_details"]["role"]


    return render_template("edit_bio.html", bio = bio, username = username, role = role)


#/update/bio
@app.route('/update/bio', methods=['POST'])
def update_bio():

    userid              = get_userid() 
    bio = request.form.get('user_bio')
    role = request.form.get('role')
    name = request.form.get('name')

    if len(bio) ==0:
        bio = None
    if len(role) ==0:
        role = None
    if len(name) ==0:
        name = None
    data = {
        "user_id"              : userid,
        "name"         : name,
        "role"         : role,
        "bio"          : bio
    }
    
    result_dict = fpr_business.user_bio_update(data)
    # flash('You were successfully logged in')
    return redirect((url_for('volunteer_redirect')))



#/donate/credits
@app.route('/donate/credits/<donated_to>', methods=['GET','POST'])
def donate_credits_for_feature(donated_to):

    user_id = get_userid()
    # logged_in = is_session_valid()


    data = {

            "donted_credits"          : request.form.get('donted_credits'),
            "comments_for_feature"    : request.form.get('comments_for_feature'),
            "feature_url"             : request.form.get('feature_url'),
            "user_id"                 : user_id,
            "donated_to"              : donated_to

    }


    result_dict = fpr_business.donate_credits(data)
    feature_url = request.form.get('feature_url')

    if result_dict["error_code"] == 0:
        return redirect(f'/features/{feature_url}')
    
@app.route('/update/socials', methods=['GET'])
def update_socials():

    s_id    = get_sid()
    userid              = get_userid() 
    
    result_dict = fpr_business.get_user_details(userid, s_id)
    
    user_details = result_dict["result"]["user_details"]
    if user_details == None:
        user_details = ""

    return render_template("edit_socials.html", user_details = user_details)


@app.route('/volunteer/<username>', methods=['GET'])
def profile_redirect(username):
    logged_in = is_session_valid()
    
    s_id    = get_sid()
    userid              = get_userid()

   
    final_username = ""
    for i in username:
        final_username= final_username+".*"+i

    final_username = final_username.lower()
    result_dict = fpr_business.get_user_details_with_username(final_username, s_id)
    if result_dict["result"]:

        userid         = result_dict["result"]["user_id"]
        result_coins   = fpr_business.get_user_coins(userid , s_id)

        if(result_coins["error_code"]!=0):
            result_coins["tactcoins"] = 0
            result_coins["tact_credits"] = 0
        else: 
            result_coins = result_coins["result"]


        result_certificates = fpr_business.get_user_recommendations(userid)


        username =  fpr_business.get_user_name(userid)

        username = username["result"]["notes"].split('@')[0]

        user_details = fpr_business.get_user_details(int(userid), s_id)
        
        if(result_certificates["error_code"] != 0):
            result_certificates = None
        else: 
            result_certificates = result_certificates["result"]["notes"]
        
        result_badges = fpr_business.get_user_badges(userid)
        
        if(result_badges["error_code"] != 0):
            result_badges = None
        else: 
            result_badges = result_badges["result"]["user_badges_images"]
        
        base_path = os.environ.get('FPR_USERFEATURE_S3_BASE')
        default_dp_path = base_path + "/featurepreneur/userfeatures/default_profile_pic.jpg"

        return render_template(
            'profile_page.html',user_details = user_details["result"]["user_details"], result_coins = result_coins, result_badges = result_badges, result_certificates = result_certificates, username = username, def_dp = default_dp_path
        )
    return  render_template(
            'error.html', 
            result = {'error_message': 'User Does Not Exist'},logged_in = logged_in
        )


@app.route('/edit/socials/submit', methods=["POST"])
@requires_session
def submit_edit_socials():

    data = {
        "github_handle"                     : request.values.get('github_handle'),
        "linkedin_handle"             : request.values.get('linkedin_handle'),
        "medium_handle"                 : request.values.get('medium_handle'),
        "kaggle_handle"               : request.values.get('kaggle_handle'),
        "user_id"                   : get_userid()
    }


    result_json = fpr_business.update_socials_links(data, get_sid())
    


    return redirect(
        url_for('update_socials')
    )

@app.route('/crowd-engine/<crowd_engine_id>/true', methods=['GET'])
def crowd_engine_page_filled(crowd_engine_id):

    s_id                = get_sid()
    userid              = get_userid()
    page                = get_page(request)

    
    result_dict = fpr_business.get_crowd_engine_links(userid, crowd_engine_id,page,1)    
    # user_details = result_dict["result"]["user_details"]
    # if user_details == None:
    #     user_details = ""
    # return str(result_dict)
    data = None
    next_page       = None
    prev_page       = None
    current_page    = None

    if result_dict["result"]["result"]:
        data = result_dict["result"]["result"]["feature_list"]
        next_page = result_dict["result"]["result"]["next_page"]
        prev_page = result_dict["result"]["result"]["prev_page"]
        current_page = result_dict["result"]["result"]["current_page"]
    
    return render_template("crowd_engine_filled.html", data = data, next_page = next_page, prev_page = prev_page, current_page = current_page, crowd_engine_id = crowd_engine_id)

@app.route('/crowd-engine/<crowd_engine_id>/false', methods=['GET'])
def crowd_engine_page_unfilled(crowd_engine_id):

    s_id                = get_sid()
    userid              = get_userid()
    page                = get_page(request)

    if int(crowd_engine_id) == 4:
        return redirect("/cnergy/annotator")
    
    result_dict = fpr_business.get_crowd_engine_links(userid, crowd_engine_id,page,0)
    # user_details = result_dict["result"]["user_details"]
    # if user_details == None:
    #     user_details = ""
    # return str(result_dict)
    data = None
    next_page       = None
    prev_page       = None
    current_page    = None

    mod = False
    if result_dict["result"]["result"]:
        data = result_dict["result"]["result"]["feature_list"]
        
        next_page = result_dict["result"]["result"]["next_page"]
        prev_page = result_dict["result"]["result"]["prev_page"]
        current_page = result_dict["result"]["result"]["current_page"]
        mod = result_dict["result"]["result"]["mod"]
  
        
    if int(crowd_engine_id) == 1:
        return render_template("crowd_engine_unfilled.html", data = data, next_page = next_page, prev_page = prev_page, current_page = current_page, crowd_engine_id = crowd_engine_id)
    if int(crowd_engine_id) == 2:
        return render_template("ml_post_edit.html", data = data, next_page = next_page, prev_page = prev_page, current_page = current_page, crowd_engine_id = crowd_engine_id, mod = mod)


@app.route('/edit/tech_keys/submit', methods=["POST"])
@requires_session
def submit_edited_techkeys():
    
    tech_keys       = request.form.getlist('tech_keys')
    links           = request.form.getlist('links')
    crowd_engine_id = request.form.get("crowd_engine_id")
    current_page_no = request.form.get("current_page_no")
    # result = akon.update_tech_links(data)

    data = {
        "tech_keys_list" : tech_keys,
        "links_list"     : links
    }
    # return video_title

    result_json = fpr_business.update_tech_links(data)

    return redirect(
        f'/crowd-engine/{crowd_engine_id}/false?page=1'
    )
 
@app.route('/edit/ml_posts/submit', methods=["POST"])
@requires_session
def submit_edited_ml_posts():
    
    post_ids       = request.form.getlist('post_id')
    posts           = request.form.getlist('editor_content')
    crowd_engine_id = 2
    current_page_no = request.form.get("current_page_no")
    # result = akon.update_tech_links(data)

    data = {
        "post_id_list" : post_ids,
        "posts_list"     : posts
    }


    result_json = fpr_business.update_ml_posts(data)

    return redirect(
        f'/crowd-engine/{crowd_engine_id}/false?page=1')
 
@app.route('/all/crowd-engines', methods = ["GET"])
@requires_session
def page_show_all_crowd_engines_get():

    result_dict = fpr_business.get_all_crowd_engine_collection()

    # return jsonify(result_dict)
    return render_template('crowd_engine_collection.html', result = result_dict['result']['result'])


@app.route('/la/dashboard', methods = ["GET"])
def la_dashboard():
    if(is_session_valid()):
    ## get_recent_links and get_top_contributors
    
        recent_links = fpr_business.la_get_recent_links()
        top_contributors = fpr_business.la_get_top_contributors()

        if recent_links["result"]:
            recent_links = recent_links["result"]['links']
        if top_contributors["result"]:
            top_contributors = top_contributors["result"]['contributors']
        user_id = get_userid()
        logged_in = is_session_valid()

        data = {
            "user_id"   : int(user_id),
            "page_size" : 100,
            "ltype"    : None,
            "_id"       : None
        }
        # result = fpr_business.la_get_user_articles(data)
        results = fpr_business.get_user_formatted_username(get_userid())

        # result1 = fpr_business.la_get_all_contributors()
        return render_template('learning-analytics-dashboard.html', context={'name': "TACT ADMIN"}, username = results["result"]["username"], recent_links = recent_links, top_contributors = top_contributors, user_id = user_id, logged_in = logged_in)
    return render_template(
        'login.html'
    )
@app.route('/la/contributors', methods = ["GET"])
def la_contributors():

    result = fpr_business.la_get_all_contributors()
    logged_in = is_session_valid()
    user_id = get_userid()
    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    results = fpr_business.la_get_user_articles(data)

    return render_template('learning-analytics-contributors.html', data = result['result']['contributors'], logged_in = logged_in, username = results["result"]["username"])

@app.route('/la/profile/<username>', methods = ["GET"])
def la_profile(username):
    

    final_username = ""
    for i in username:
        final_username= final_username+".*"+i

    final_username = final_username.lower()

    data = {
        "username"   : final_username,
    }

    result = fpr_business.la_get_user_total_score(data)
    user_id = result["result"]["user_id"]
    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    result1 = fpr_business.la_get_user_articles(data)
    results = fpr_business.get_user_formatted_username(get_userid())

    logged_in = is_session_valid()
    return render_template('learning-analytics-profile.html', user_id = user_id, data = result["result"],username = results["result"]["username"], result = result1["result"]["data"], logged_in = logged_in)
 

@app.route('/la/<username>/articles', methods = ["GET"])
@requires_session
def user_articles(username):

    final_username = ""
    for i in username:
        final_username= final_username+".*"+i

    final_username = final_username.lower()
    final_username = final_username.replace(" ", "")

    data = {
        "username"   : final_username,
    }

    data = {
        "user_id"   : get_userid(),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    
    result = fpr_business.la_get_user_articles(data)
    return render_template('learning-analytics-user_articles.html', data = result['result']['data'], username = result["result"]["username"])



@app.route('/la/user-articles/links/<user_id>', methods = ["GET"])
def la_contributor_articles(user_id):


    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    
    result = fpr_business.la_get_user_articles(data)

    return render_template('learning-analytics-user_links.html', data = result["result"]["data"], username = result["result"]["username"])



@app.route('/la/make_link_private', methods=["POST"])
@requires_session
def la_make_link_private():
    
    title       = request.form.get('title')
    user_id     = get_userid()
 
    # result = akon.update_tech_links(data)
    data = {
        "user_id" : user_id,
        "title"     : title
    }

    # return video_title

    result_json = fpr_business.la_make_link_private(data)

    return redirect(
        '/la/dashboard'
    )

@app.route('/la/mylist/make_link_private', methods=["POST"])
@requires_session
def la__mylist_make_link_private():
    
    title       = request.form.get('title')
    user_id     = get_userid()
 
    # result = akon.update_tech_links(data)
    data = {
        "user_id" : user_id,
        "title"     : title
    }

    result_json = fpr_business.la_make_link_private(data)
    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    
    result = fpr_business.la_get_user_articles(data)


    username = result["result"]["username"] 

    return redirect(
        f'/la/{username}/articles'
    )
    

@app.route('/la/mylist/make_link_public', methods=["POST"])
@requires_session
def la__mylist_make_link_public():
    
    title       = request.form.get('title')
    user_id     = get_userid()
 
    # result = akon.update_tech_links(data)
    data = {
        "user_id" : user_id,
        "title"     : title
    }

    result_json = fpr_business.la_make_link_public(data)
    
    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    
    result = fpr_business.la_get_user_articles(data)


    username = result["result"]["username"] 

    return redirect(
        f'/la/{username}/articles'
    )

@app.route('/la/delete/article', methods=["POST"])
@requires_session
def la_delete_article():
    
    title       = request.form.get('title')
    created_at       = request.form.get('created_at')

    
    user_id     = get_userid()
 
    # result = akon.update_tech_links(data)
    data = {
        "user_id" : user_id,
        "title"     : title,
        "created_at" : created_at
    }

    result_json = fpr_business.la_delete_article(data)

    return redirect(
        '/la/dashboard'
    )

@app.route('/la/mylist/delete/article', methods=["POST"])
@requires_session
def la_my_list_delete_article():
    
    title       = request.form.get('title')
    created_at       = request.form.get('created_at')

    
    user_id     = get_userid()
    
    data = {
        "user_id" : user_id,
        "title"     : title,
        "created_at" : created_at
    }

    result_json = fpr_business.la_delete_article(data)
    # result = akon.update_tech_links(data)
    data = {
        "user_id"   : int(user_id),
        "page_size" : 100,
        "ltype"    : None,
        "_id"       : None
    }
    
    result = fpr_business.la_get_user_articles(data)

    username = result["result"]["username"]

    return redirect(
        f'/la/{username}/articles'
    )

@app.route('/la/user/get/contributions/<user_id>', methods = ["GET"])
def la_get_user_contributions(user_id):
    heatmap_data = fpr_business.la_get_user_contributions(user_id)
    return jsonify(heatmap_data["result"]["contributions"])


@app.route('/la-search', methods=["POST"])
@requires_session
def la_link_search():

    word = request.get_data()
    
    word = word.decode()

    if len(word)>2:
        data = {
            "query_word"  : word
        }
        result = fpr_business.la_search_article(data)
        return {"result":result["result"]["search_results"]}
    return {"result":["hey"]}



@app.route('/ML-posts', methods = ["GET"])
@requires_session
def ml_posts():
    page = get_page(request)
    result = fpr_business.get_daily_ml_posts(page)
    prev_page = None
    current_page = None
    next_page = None


    if result["result"]:
        data = result["result"]["posts_history"]["posts_list"]
        prev_page = result["result"]["posts_history"]["prev_page"]
        current_page = result["result"]["posts_history"]["current_page"]
        next_page = result["result"]["posts_history"]["next_page"]

    return render_template('ml_posts.html', data = data, prev_page = prev_page, current_page = current_page, next_page = next_page)

@app.route('/add/ml_posts', methods=['GET'])
def add_ml_posts():

    
    
    # result_dict = fpr_business.add_ml_posts()

    return render_template("ml_posts_add.html")

@app.route('/add/ml_posts', methods=["POST"])
@requires_session
def submit_add_ml_posts():
    user_id     = get_userid()
    ml_post       = request.form.get('editor_content')


    # ml_post       = request.form.get('ml_post')
   
 
    # result = akon.update_tech_links(data)
    data = {
        "user_id"     : user_id,
        "ml_post"     : ml_post
    }

    result_json = fpr_business.add_ml_posts_submit(data)

    return redirect(
        '/crowd-engine/2/false'
    )



@app.route('/delete/ml_post/<mlpost_id>', methods=['GET'])
def delete_ml_posts(mlpost_id):

    res = fpr_business.delete_ml_post(mlpost_id)
    
    
    # result_dict = fpr_business.add_ml_posts()

    return redirect("/crowd-engine/2/false")


@app.route('/la/settings', methods = ["GET"])
@requires_session
def la_settings():

    result_dict = fpr_business.get_la_sites(get_userid())

    # return jsonify(result_dict)
    # link_list = []


    # for link in result_dict['result']['sites']:
    #     link_list.append({"display_link":link['link'].split('/')[2], "link" : link['link']})
    results = fpr_business.get_user_formatted_username(get_userid())
    return render_template('learning-analytics-settings.html' ,username = results["result"]["username"], result = result_dict['result']['sites'] ) 



@app.route('/la/settings/save', methods = ["POST"])
@requires_session
def la_settings_save():


    links = request.form.getlist('sites')
    
    data = {
        "sites"     : links,
        "user_id"   : get_userid()
    }

    result_dict = fpr_business.save_la_config(data)
    resp = make_response(redirect('/la/settings'))
        
    # for link in result_dict["result"]["sites"]:
    resp.set_cookie('sites', json.dumps({"sites":result_dict["result"]["sites"]}))


    # # return jsonify(result_dict)
    # link_list = []
    # for link in result_dict['result']['sites']:
    #     link_list.append(link['link'].split('/')[2]) 
    # return render_template('learning-analytics-settings.html' , result = link_list ) 
    return resp

@app.route('/ama/info/<ama_event_id>', methods = ["GET"])
@requires_session
def ama_info(ama_event_id):

    result_dict = fpr_business.get_ama_info(ama_event_id)

    # results = fpr_business.get_user_formatted_username(get_userid())
    return render_template('ama-info.html', result = result_dict["result"]["ama info"]) 

@app.route('/ama/sessions/', methods = ["GET"])
@requires_session
def ama_info_main():

    result_dict = fpr_business.get_all_ama_info()

    # results = fpr_business.get_user_formatted_username(get_userid())
    # return jsonify(result_dict) 
    return render_template('ama-info-main.html', data = result_dict["result"]["ama_events"]) 


@app.route('/cnergy/dashboard', methods = ["GET"])
@requires_session
def cnergy_dash():

    return render_template('cnergy_dash.html') 

@app.route('/cnergy/annotator', methods = ["GET"])
@requires_session
def annotator():

    return render_template('annotator.html') 

# @app.route('/annotator/skip/<skip_value>', methods = ["GET"])
# @requires_session
# def annotator_skip_page():

#     try:
#         session['skip_value'] += 1
#     except:
#         session['skip_value'] = 1
    
#     return 'success'


@app.route('/annotator/get_next_page/<skip_value>', methods = ["GET"])
@requires_session
def annotator_get_next_page(skip_value=0):

    # try:
    #     skip_value = session['skip_value']
    # except:
    #     skip_value = 0

    result = fpr_business.get_next_annotator_text(user_id = get_userid(), skip_value = skip_value)
    # result = fpr_business.get_next_annotator_text(1)
    # if not result["result"]["batch_status"]:
    #     return redirect("/")
    return result["result"]



@app.route('/annotator/save-data', methods=["POST"])
@requires_session
def annotator_save_data():
    val = request.get_json()

    val["user_id"] =  get_userid()

    # ml_post       = request.form.get('ml_post')
    
    # result = akon.update_tech_links(data)

    # return video_title

    result_json = fpr_business.save_annotation_data(val)

    return "true"

@app.route('/fs3', methods = ["GET"])
# @requires_session
def featurethon_season_3():

    return render_template('featurethon-season-3.html') 

@app.route('/thamizhai', methods = ["GET"])
def thamizhai():

    return render_template('thamizhai.html') 

@app.route('/fs3/leaderboard', methods = ["GET"])
# @requires_session
def fs3_leaderboard():

    result = fpr_business.get_fs3_leaderboard()

    return render_template('fs3-leaderboard.html', data = result["result"]["team_score"]) 

@app.route("/fs3/growth-chart", methods = ['GET'])
# @requires_session
def fs3_dashboard():

    # page = get_page(request)

    result = fpr_business.get_fs3_team_score_dashboard()
    # print (resp)
    # if("result" in resp):
    #     result = resp['result']["result"]
    #     result['current_url_part'] = f'crowd-engine/{crowd_engine_id}'
    # else:
    #     result = {}
    #     result['current_url_part'] = f'crowd-engine/{crowd_engine_id}'
    #     result["current_page"] = 1


    # return jsonify(result)

    data = result["result"]["result"]
    return render_template('fs3-dashboard.html', myresult = data)

@app.route('/subscribe/courses/ttc/<course_id>', methods = ["GET"])
@requires_session
def subscribe_courses_ttc_api(course_id):
    
    s_id    = get_sid()
    userid  = get_userid()     
    result_dict = fpr_business.subscribe_courses_ttc(userid, s_id, course_id)

    if result_dict["error_code"] == 0:
    # return jsonify(result_dict)
        return redirect (url_for('page_show_courses_ttc_get'))
    return redirect(url_for('page_show_all_courses_get'))

@app.route("/subscribe/courses/ttc/credits/<course_id>", methods = ['GET'])
@requires_session
def get_credits_info_api(course_id):

    s_id    = get_sid() 
    userid  = get_userid() 

    result = fpr_business.get_credits_info(userid, s_id, course_id)

    result_dict2 = fpr_business.get_one_course_ttc_info(course_id, s_id)

    user_credits = result["result"]["user_total_credit_coins"]

    subscription_cost = result["result"]["subscription_cost"]

    remaining_credits = result["result"]["remaining_credits"]
    
    return render_template('course_ttc_credits.html', course_id=course_id,user_credits = user_credits, subscription_cost = subscription_cost, remaining_credits = remaining_credits,title= result_dict2["result"]["course"]["name"])

@app.route('/random-challenge', methods = ["GET"])
# @requires_session
def get_all_random_challenge_info_api():

    logged_in = is_session_valid()

    result_dict = fpr_business.get_all_random_challenge_info()

    # results = fpr_business.get_user_formatted_username(get_userid())
    # return jsonify(result_dict) 
    return render_template('random-challenge-titles.html', data = result_dict["result"]["result"], logged_in = logged_in) 


@app.route('/random-challenge/<random_challenge_url>', methods = ["GET"])
# @requires_session
def get_one_random_challenge_info_api(random_challenge_url):


    logged_in = is_session_valid() 

    random_challenge_id = int(random_challenge_url.split('-')[-1])


    import random
    if logged_in:
        user_id = get_userid() 
        random_challenge_status = fpr_business.get_user_random_challenge_status(user_id, random_challenge_id)['result']
    
    else:
        random_challenge_status =  {
            "result" : []
        }
    result_dict = fpr_business.get_one_random_challenge_info(random_challenge_id)
    result_dict2 = fpr_business.get_random_challenge_users_count(random_challenge_id)['result']

    result_dict3 = fpr_business.get_random_challenge_quotes()

    random_completed_quotes = random.choice(result_dict3["result"]["random_challenge_completed_quotes"])

    random_giveup_quotes = random.choice(result_dict3["result"]["random_challenge_giveup_quotes"])
    
    if result_dict["result"]["result"]:
 
        return render_template('random-challenge.html', data = result_dict["result"]["result"][0], random_challenge_status=random_challenge_status, random_challenge_id=random_challenge_id, 
            completed_users_count=result_dict2["completed_users"], engaged_users_count=result_dict2['engaged_users'], logged_in = logged_in, completed_quotes = random_completed_quotes, giveup_quotes = random_giveup_quotes, random_challenge_url=random_challenge_url) 

    else:
        result ={
        "error_message" : "OOPS! You have entered wrong url"
        }
    
        return render_template("error.html", result =result, logged_in = logged_in)


@app.route('/engage/random-challenge/<random_challenge_url>', methods = ["GET"])
@requires_session
def start_learning_challenge_for_user(random_challenge_url):
    # logged_in = is_session_valid()
    # if logged_in:

    random_challenge_id = int(random_challenge_url.split('-')[-1])


    user_id = get_userid() 
    

    # data = {"challenge_id": int(random_challenge_id), "user_id":user_id} 

    result_dict = fpr_business.take_up_random_challenge(user_id,random_challenge_id)

    # session["redirect_url"] = f"/random-challenge/{random_challenge_id}"

    return redirect(f"/random-challenge/{random_challenge_url}")
    
    # else:
    #     session["redirect_url"] = f"/random-challenge/{random_challenge_id}"
    #     return redirect(url_for('page_login_get'))

@app.route('/delete/user/random-challenge/<random_challenge_url>', methods = ["GET"])
@requires_session
def delete_user_random_challenge_api(random_challenge_url):

    random_challenge_id = int(random_challenge_url.split('-')[-1])

    user_id = get_userid()

    # data = {"challenge_id": int(random_challenge_id), "user_id":user_id} 

    result_dict = fpr_business.delete_user_random_challenge(user_id, random_challenge_id)

    return redirect(f"/random-challenge/{random_challenge_url}")


@app.route('/complete/user/random-challenge/<random_challenge_url>', methods = ["GET"])
@requires_session
def complete_user_random_challenge_api(random_challenge_url):

    random_challenge_id = int(random_challenge_url.split('-')[-1])

    user_id = get_userid()

    data = {"challenge_id": int(random_challenge_id), "user_id":user_id} 

    result_dict = fpr_business.complete_random_challenge(data)

    return redirect(f"/random-challenge/{random_challenge_url}")

@app.route('/donate/tact-credits', methods = ["GET"])
@requires_session
def test_user_info():
    from operator import itemgetter

    user_id     = get_userid()
    s_id    = get_sid()
    username = get_user_name_with_user_id(user_id)
    username = username["result"]["notes"].split('@')[0]

    result_dict = fpr_business.get_all_usernames_and_email()
    result_dict2 = fpr_business.get_one_user_credits_donations_history(user_id)

    result_json   = fpr_business.get_user_coins(user_id, s_id)
    received = result_dict2["result"]["user_credits_received"]
    donated = result_dict2["result"]["user_credits_donated"]
    result = received + donated
    # tact_credits = result_json["result"]
    
    
    # result = sorted(result)
    
    result = sorted(result, key=itemgetter('created_at'), reverse=True)
    # donated_username = donated_username.split('@')[0]

    # return jsonify(result_dict)
    return render_template("tact-credits.html", data = result_dict, received = result_dict2["result"]["user_credits_received"], donated = result_dict2["result"]["user_credits_donated"], username = username, tact_credits = result_json["result"], result =result)

@app.route('/tact-credits/donate', methods=["POST"])
@requires_session
def tact_credits_donate_post_api():

    user_id     = get_userid()
    
    donated_to  = request.form.get('donated_to')
    donated_credits = request.form.get('donated_credits')
    donor_comments = request.form.get("donor_comments")

    data = {
        "user_id"     : user_id,
        "donated_to"     : donated_to,
        "donated_credits" : donated_credits,
        "donor_comments" : donor_comments
    }
   
    result_json = fpr_business.tact_credits_donate_post(data)

    return redirect(
        '/donate/tact-credits'
    )


@app.route("/username-regex-search", methods = ["POST"])
@requires_session
def check_regex_func():

    val = request.get_json()

    result_dict = fpr_business.username_regex_search(val)

    return jsonify(result_dict)

@app.route('/privacy-policy', methods=["GET"])
@requires_session
def privacy_policy():

    return render_template(
        'privacy_policy.html'
    )

@app.route('/new-course', methods=["GET"])
@requires_session
def course2():

    return render_template(
        'amazon.html'
    )

@app.route('/new-course2', methods=["GET"])
@requires_session
def course3():

    return render_template(
        'coursepage-3.html'
    )
#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

if __name__ == '__main__':
    app.run('0.0.0.0', app.config["PORT"], True)
