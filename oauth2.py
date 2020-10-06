from flask import render_template, session, redirect
from flask_dance.contrib import azure, github
import flask_dance.contrib
import os

from CTFd.auth import confirm, register, reset_password, login
from CTFd.models import db, Users
from CTFd.utils import set_config
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user

from CTFd import utils

import boto3
import base64
from botocore.exceptions import ClientError
import json


def get_secret():

    secret_name = "ctf_azure_sso"
    region_name = "eu-west-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    else:
        decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return json.loads(decoded_binary_secret)


def load(app):

    ########################
    # Plugin Configuration #
    ########################
    aws_secret = get_secret()
    authentication_url_prefix = "/auth"
    oauth_client_id = aws_secret['OAUTHLOGIN_CLIENT_ID']
    oauth_client_secret = aws_secret['OAUTHLOGIN_CLIENT_SECRET']
    oauth_provider = "azure"
    create_missing_user = True

    ##################
    # User Functions #
    ##################
    def retrieve_user_from_database(username):
        user = Users.query.filter_by(email=username).first()
        if user is not None:
            log('logins', "[{date}] {ip} - " + user.name + " - OAuth2 bridged user found")
            return user
    def create_user(username, displayName):
        with app.app_context():
            user = Users(email=username, name=displayName.strip())
            log('logins', "[{date}] {ip} - " + user.name + " - No OAuth2 bridged user found, creating user")
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            login_user(user)
            return user
    def create_or_get_user(username, displayName):
        user = retrieve_user_from_database(username)
        if user is not None:
            login_user(user)
            return user
        if create_missing_user:
            return create_user(username, displayName)
        else:
            log('logins', "[{date}] {ip} - " + user.name + " - No OAuth2 bridged user found and not configured to create missing users")
            return None

    ##########################
    # Provider Configuration #
    ##########################
    provider_blueprints = {
        'azure': lambda: flask_dance.contrib.azure.make_azure_blueprint(
            login_url='/azure',
            client_id=oauth_client_id,
            client_secret=oauth_client_secret,
            redirect_url=authentication_url_prefix + "/azure/confirm"),
        'github': lambda: flask_dance.contrib.github.make_github_blueprint(
            login_url='/github',
            client_id=oauth_client_id,
            client_secret=oauth_client_secret,
            redirect_url=authentication_url_prefix + "/github/confirm")
    }

    def get_azure_user():
        user_info = flask_dance.contrib.azure.azure.get("/v1.0/me").json()
        return create_or_get_user(
            username=user_info["userPrincipalName"],
            displayName=user_info["displayName"])
    def get_github_user():
        user_info = flask_dance.contrib.github.github.get("/user").json()
        return create_or_get_user(
            username=user_info["email"],
            displayName=user_info["name"])

    provider_users = {
        'azure': lambda: get_azure_user(),
        'github': lambda: get_github_user()
    }

    provider_blueprint = provider_blueprints[oauth_provider]() # Resolved lambda
    
    #######################
    # Blueprint Functions #
    #######################
    @provider_blueprint.route('/<string:auth_provider>/confirm', methods=['GET'])
    def confirm_auth_provider(auth_provider):
        if not auth_provider in provider_users:
            return redirect('/')

        provider_user = provider_users[oauth_provider]() # Resolved lambda
        session.regenerate()
        return redirect('/')

    app.register_blueprint(provider_blueprint, url_prefix=authentication_url_prefix)
    print(app.register_blueprint)

    ###############################
    # Application Reconfiguration #
    ###############################
    # ('', 204) is "No Content" code
    set_config('registration_visibility', False)
    app.view_functions['auth.login'] = lambda: redirect(authentication_url_prefix + "/" + oauth_provider)
    app.view_functions['auth.register'] = lambda: ('', 204)
    app.view_functions['auth.reset_password'] = lambda: ('', 204)
    app.view_functions['auth.confirm'] = lambda: ('', 204)     
