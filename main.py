def extract_url_features(url):
    features = {
'url_length': len(url),
'hostname_length': len(urlparse(url).netloc),
'path_length': len(urlparse(url).path),
'count-': url.count('-'),
'count@': url.count('@'),
'count?': url.count('?'),
'count%': url.count('%'),
'count.': url.count('.'),
'count=': url.count('='),
'count_http': url.count('http'),
'count_https': url.count('https'),
'count_www': url.count('www'),
'ends_exe': int(url.endswith('.exe')),
'ends_org': int(url.endswith('.org')),
'ends_net': int(url.endswith('.net')),
'ends_edu': int(url.endswith('.edu')),
'ends_gov': int(url.endswith('.gov')),
'ends_mil': int(url.endswith('.mil')),
'ends_com': int(url.endswith('.com')),
'count_&': url.count('&'),
'count_!': url.count('!'),
'count_//': url.count('//'),
'count_#': url.count('#'),
'first_subdir_length': first_subdir_length(url),
'count_login_signin': count_login_signin(url),
'count_letters': letter_count(url),
'count_digits': digit_count(url),
'count_dir': no_of_dir(url),
'use_of_ip': having_ip_address(url),
'short_url': shortening_service(url),
'fd_length': fd_length(url),
'tld_length': get_tld_length(url)
}
    return features

import re
import tldextract
from urllib.parse import urlparse
import pandas as pd


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def first_subdir_length(url):
    url_path = urlparse(url).path
    subdirs = url_path.split('/')
    if len(subdirs) > 1:
        return len(subdirs[1])
    else:
        return 0

def count_login_signin(url):
    lower_url = url.lower()
    return lower_url.count('login') + lower_url.count('signin')

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def having_ip_address(url):
    match = re.search(
        '(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        '([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    else:
        return 1

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def get_tld_length(url):
    ext = tldextract.extract(url)
    tld = ext.suffix

    try:
        return len(tld)
    except:
        return -1


def dict_values_to_list(feature_dict):
    return list(feature_dict.values())
# url = "bopsecrets.org/rexroth/cr/1.htm"
# features_dict = extract_url_features(url)
# print(features_dict)
# features_df = dict_values_to_list(features_dict)
# print(features_df)



from keras.models import load_model
import joblib
import numpy as np

from keras.models import load_model
import joblib
import numpy as np

def predict_url(url):
    # Load the saved model
    saved_model = load_model("f31_model_final_0_tld.h5")

    # Load the saved scaler object
    loaded_scaler = joblib.load("scaler.joblib")

    # Extract the features from the custom URL
    features_dict = extract_url_features(url)
    features_list = dict_values_to_list(features_dict)

    # Scale the features
    scaled_features = loaded_scaler.transform([features_list])

    # Make a prediction using the loaded model
    prediction = saved_model.predict(scaled_features)

    # Get the predicted class
    predicted_class = np.argmax(prediction, axis=1)
    if predicted_class == 0:
        return f"Safe Url --> {url}"
    elif predicted_class == 1:
        return f"Malicious Url --> {url}"
    elif predicted_class == 2:
        return f"Phishing Url --> {url}"
    elif predicted_class == 3:
        return f"Defacement Url --> {url}"
    else:
        return "Unknown"

# -------------------------------------------------------------
from flask import Flask, render_template, request, jsonify
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    result = predict_url(url)
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)







