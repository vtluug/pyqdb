#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

import string
import logging

# flask includes
from flask import Flask, request, session, g, \
                  redirect, url_for, abort, render_template, \
                  flash, make_response
from flask_cache import Cache
from werkzeug.contrib.fixers import ProxyFix

# extensions
from ratelimitcache import ratelimit, ratelimit_post

# local includes
from data_models import Quote, Tag, Vote
from jsonify import jsonify
import flask_override
from db import db
from sql import db_session # yuck, we shouldnt dep on this
from basic_auth import FlaskRealmDigestDB
from news import News
from rest import build_link, add_loc_hdr, add_link_hdr
from jinja2 import Markup


# app config
#SECRET_KEY = '\xfb\x12\xdf\xa1@i\xd6>V\xc0\xbb\x8fp\x16#Z\x0b\x81\xeb\x16'
SECRET_KEY = 'SUPERSECRETAPIKEY'
DEBUG = True
CACHE_TYPE = 'simple'

app = Flask(__name__)
app.request_class = flask_override.Request
app.config.from_object(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

cache = Cache(app)

navs = [
    build_link('/top', 'pyqdb/quotes', Quote.list_json_mimetype, title='Top'),
    build_link('/quotes', 'pyqdb/quotes', Quote.list_json_mimetype, title='Browse'),
    build_link('/random', 'pyqdb/quotes', Quote.list_json_mimetype, title='Random'),
    build_link('/tags', 'pyqdb/tags', Tag.list_json_mimetype, title='Tags'),
    build_link('/search', '', 'application/json', title='Search'),
    build_link('/quotes/new', 'pyqdb/quote/new', Quote.json_mimetype, title='Submit')
]

auth = FlaskRealmDigestDB()
auth.add_user('admin', 'test')

# Setup logging
logger = logging.getLogger('pyqdb')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('pyqdb.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)


## Routes and Handlers ##
@app.route('/')
def welcome():
    if request.wants_json():
        links = navs
        links.append(build_link('/', 'self', 'application/json'))
        root = { 'version': '0.1',
                 'title': 'VT Bash',
                 'links': links }
        return jsonify(root, 'application/json')
    news = News()
    return render_template('index.html', nav=navs, news=news.news)

@app.route('/admin')
@auth.requires_auth
def admin():
    session['user'] = request.authorization.username
    return "Yup.\n Hello, %s" % (session['user'])

@app.route('/auth')
def authApi():
    if not request.authorization:
        return auth.authenticate()
    print("REQUEST", file=sys.stderr)
    print(request, file=sys.stderr)
    return redirect('/')

@app.route('/quotes/new', methods=['GET'])
def new_quote():
    if request.wants_json():
        rs = jsonify({'body': "Quote here", 'tags': [], 'link': build_link('/quotes', 'pyqdb/quote/new', Quote.json_mimetype, method='post', title='Create a new quote')}, Quote.json_mimetype)
        add_link_hdr(rs, '/quotes', 'pyqdb/quote/new')
        return rs
    return render_template('submit.html', nav=navs)

@app.route('/quotes', methods=['POST'])
@ratelimit_post(cache=cache.cache, minutes=1, requests=5)
def create_quote():
    if request.provided_json():
        return create_quote_json()
    else:
        return create_quote_form()

def validate_quote(body, tags, key=''):
    body_valid = True
    tags_valid = True
    key_valid = key == SECRET_KEY
    if len(body) > 10*1024: # 10kb, arbitrary limit
        body_valid = False
    for tag in tags:
        if len(tag) > 15:
            tags_valid = False
            break
    return body_valid, tags_valid, key_valid

def create_quote_json():
    ip = request.remote_addr
    data = request.json
    
    try:
        body_valid, tags_valid, key_valid = validate_quote(data['body'], data['tags'], data['key'])
    except KeyError:
        quote = ''
        body_valid = False
        tags_valid = False
        key_valid = False

    if key_valid and body_valid and tags_valid:
        quote = Quote(data['body'], ip)
        quote.tags = list(map(Tag, data['tags'].split(',')))
        quote = db.put(quote) # grabbing return val isn't strictly necessary
    else:
        quote = ''

    if request.wants_json():
        return create_quote_resp_json(quote, body_valid, tags_valid, key_valid)
    else:
        return create_quote_resp_html(quote, body_valid, tags_valid, key_valid)
     
def create_quote_form():
    ip = request.remote_addr
    type = request.headers['Content-Type']

    tags = []
    tags_valid = True
    body_valid = True

    content = request.form['quote']

    # strip trailing whitespace at each line
    content_lines = content.splitlines()
    for i,l in enumerate(content_lines):
        content_lines[i] = l.rstrip()
    content = '\n'.join(content_lines) 

    logger.info(content)
    tags_raw = request.form['tags'] 
    # a smidgen of validation
    if len(tags_raw) > 100:
        tags_valid = False
    else:
        tags = list(map(str.strip, tags_raw.split(',')))
        body_valid, tags_valid, key_valid = validate_quote(content, tags)

    quote = None
    if body_valid and tags_valid:
        quote = Quote(content, ip)
        quote.tags = list(map(Tag, tags))
        quote = db.put(quote) # grabbing return val isn't strictly necessary

    if request.wants_json():
        return create_quote_resp_json(quote, body_valid, tags_valid)
    else:
        return create_quote_resp_html(quote, body_valid, tags_valid)

def create_quote_resp_json(quote, body_valid, tags_valid, key_valid): 
    error = { 'error': 'validation', 'error_msg': '' }
    if not body_valid:
        error['error_msg'] += 'Body too large'
    if not tags_valid:
        error['error_msg'] += 'Tags too large'
    if not key_valid:
        error['error_msg'] += 'Invalid Key'
    if not body_valid or not tags_valid or not key_valid:
        rs = jsonify(error, 'application/vnd.pyqdb-error+json')
        rs.status_code = 413
        return rs
     
    rs = jsonify(quote, Quote.json_mimetype)
    add_loc_hdr(rs, '/quotes/%s' % (quote.id))
    rs.status_code = 201
    return rs 

def create_quote_resp_html(quote, body_valid, tags_valid, key_valid): 
    if not body_valid:
        flash('Error: Quote too big', 'error')
    if not tags_valid:
        flash('Error: Tags too big', 'error')
    if not key_valid:
        flash('Error: Key Invalid', 'error')

    if body_valid and tags_valid and key_valid:
        flash('Quote Submitted. Thanks!', 'success')

    return render_template('message.html', nav=navs)

# convenience function to parse the querystring 
def parse_qs(args, tag = None):
    incr = 15
    start = args.get('start', 0, type=int)
    if tag:
        count = db.tag_count(tag)
    else:
        count = db.count()
    next = min(start+incr, count)
    prev = max(start-incr, 0)
    return (incr, start, next, prev )


@app.route('/quotes')
def latest():
    incr,start,next,prev = parse_qs(request.args)
    quotes = db.latest(incr, start)
    admin = auth.isAuthenticated
    if request.wants_json():
        next_link = '/quotes?start=%s' % (next)
        prev_link = '/quotes?start=%s' % (prev)
        json = {'quotes': quotes, 'links': [ 
            build_link(next_link, 'pyqdb/quotes/next', Quote.list_json_mimetype),
            build_link(prev_link, 'pyqdb/quotes/prev', Quote.list_json_mimetype) ]
        }
        rs = jsonify(json, Quote.list_json_mimetype)
        add_link_hdr(rs, next_link, 'pyqdb/quotes/next')
        if start > 0:
            add_link_hdr(rs, prev_link, 'pyqdb/quotes/prev')
        return rs
    return render_template('quotes.html', nav=navs, quotes=quotes, page='quotes', next=next, prev=prev, isAdmin=admin)

@app.route('/search')
def search():
    incr,start,next,prev = parse_qs(request.args)
    query = request.args.get('query', None)
    if not query:
        if request.wants_json():
            return json_nyi()
        return render_template('search.html', nav=navs)

    if request.wants_json():
        return json_nyi()
    return render_template('search.html', nav=navs, quotes=db.search(query, incr, start), title="Search Results for '%s'" %(query), next=next, prev=prev, page="search", query=query)


@app.route('/tags')
def tags():
    format = request.args.get('format', 'html')
    if request.wants_json():
        return jsonify( db.tags(), Tag.list_json_mimetype )
    return render_template('tags.html', nav=navs)

@app.route('/tags/<string:tag>')
def tag(tag):
    incr,start,next,prev = parse_qs(request.args, tag)
    quotes = db.tag(tag, incr, start)
    admin = auth.isAuthenticated(request)
    print(request)
    page = 'tags/%s' % (tag)
    if request.wants_json():
        return json_nyi()
    return render_template('quotes.html', nav=navs, quotes=quotes, page=page, next=next, prev=prev, title="Quotes Tagged '%s'" %(tag), isAdmin=admin)

@app.route('/top')
def top():
    incr,start,next,prev = parse_qs(request.args)
    admin = auth.isAuthenticated(request)
    print(request)
    if request.wants_json():
        return json_nyi()
    return render_template('quotes.html', nav=navs, quotes=db.top(incr, start), page='top', next=next, prev=prev, isAdmin=admin)

@app.route('/random')
def random():
    admin = auth.isAuthenticated(request)
    print(request)
    if request.wants_json():
        return json_nyi()
    return render_template('quotes.html', nav=navs, quotes=db.random(15), isAdmin=admin)

@app.route('/quotes/<int:quote_id>')
def single(quote_id):
    quotes = [ db.get(quote_id) ]
    admin = auth.isAuthenticated(request)
    print(request)
    if None in quotes:
        abort(404)
    if request.wants_json():
        return json_nyi()
    return render_template('quotes.html', nav=navs, quotes=quotes, isAdmin=admin)

@app.route('/quotes/<int:quote_id>', methods=['DELETE'])
def remove(quote_id):
    if not auth.isAuthenticated:
        abort(403)
    quote = db.get(quote_id)
    if quote is None:
        abort(404)
    if request.provided_json():
        return json_nyi()
    db.delete(quote)
    return "success"

@app.route('/quotes/<int:quote_id>/votes', methods=['PUT'])
def cast_vote(quote_id):
    ip = request.remote_addr
    quote = db.get(quote_id)
    if quote is None:
        abort(404)
    if request.provided_json():
        return json_nyi()
    else:
        type = request.form['type']

    if type == "up":
        quote = db.up_vote(quote_id, ip)
    elif type == "down":
        quote = db.down_vote(quote_id, ip)
    else:
        abort(400)
    return jsonify(quote, Quote.json_mimetype)

@app.route('/quotes/<int:quote_id>/votes')
def fetch_votes(quote_id):
    quote = db.get(quote_id)
    if quote is None:
        abort(404)
    json = { 'links': [ 
                        build_link('/quotes/%s' %(quote_id), 'pyqdb/quote', Quote.json_mimetype),
                        build_link('/quotes/%s/votes' %(quote_id), 'pyqdb/quote/cast-vote', Vote.json_mimetype, method='put') ],
              'type': '', # up or down
              'id': quote_id
    }
    return jsonify(json, Vote.json_mimetype)

@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == '__main__':
    app.run(port=8080)
