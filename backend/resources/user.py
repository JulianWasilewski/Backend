"""User Resource."""
import re
import validators
from flask import Blueprint, request, jsonify
from jwt import DecodeError
from sqlalchemy.orm.exc import NoResultFound

from backend.blockstack_auth import BlockstackAuth
from backend.database.model import User
from backend.resources.helpers import auth_user, db_session_dec
from backend.smart_contracts.web3 import WEB3

BP = Blueprint('user', __name__, url_prefix='/api/users')
HTTP_CODE_OK = 200
HTTP_CODE_CREATED = 201
HTTP_CODE_ERROR_BAD_REQUEST = 400
HTTP_CODE_ERROR_NOT_FOUND = 404

@BP.route('', methods=['GET'])
@db_session_dec
def users_get(session):
    """
    Handles GET for resource <base>/api/users .

    :return: json data of users
    """
    args = request.args
    name_user = args.get('username')

    results = session.query(User)

    if name_user:
        results = results.filter(User.usernameUser.contains(name_user))
    else:
        return jsonify({'error': 'missing Argument'}), HTTP_CODE_ERROR_BAD_REQUEST

    json_data = []
    for result in results:
        balance = WEB3.eth.getBalance(result.publickeyUser)

        json_data.append({
            'id': result.idUser,
            'username': result.usernameUser,
            'firstname': result.firstnameUser,
            'lastname': result.lastnameUser,
            'email': result.emailUser,
            'group': result.group,
            'publickey': result.publickeyUser,
            'balance': balance,
        })

    return jsonify(json_data)


@BP.route('/<id>', methods=['GET'])
@db_session_dec
def user_id(session, id):  # pylint:disable=redefined-builtin,invalid-name
    """
    Handles GET for resource <base>/api/users/<id> .
    :parameter id of a User
    :return: the User
    """
    id_user = id

    try:
        if id_user:
            int(id_user)
    except ValueError:
        return jsonify({'error': 'bad argument'}), HTTP_CODE_ERROR_BAD_REQUEST

    results = session.query(User)

    try:
        if id_user:
            results = results.filter(User.idUser == id_user).one()
            balance = WEB3.eth.getBalance(results.publickeyUser)
    except NoResultFound:
        return jsonify({'error': 'User not found'}), HTTP_CODE_ERROR_NOT_FOUND

    json_data = {
        'id': results.idUser,
        'username': results.usernameUser,
        'firstname': results.firstnameUser,
        'lastname': results.lastnameUser,
        'email': results.emailUser,
        'group': results.group,
        'publickey': results.publickeyUser,
        'balance': balance,
    }
    return jsonify(json_data), HTTP_CODE_OK


@BP.route('', methods=['PUT'])
@auth_user
def user_put(user_inst):
    """
    Handles PUT for resource <base>/api/users .
    :return: "{'status': 'Daten wurden geändert'}", 200
    """
    firstname = request.headers.get('firstname', default=None)
    lastname = request.headers.get('lastname', default=None)
    email = request.headers.get('email', default=None)

    if email is not None and not validators.email(email):
        return jsonify({'error': 'email is not valid'}), HTTP_CODE_ERROR_BAD_REQUEST

    if None in [firstname, lastname, email]:
        return jsonify({'error': 'Missing parameter'}), HTTP_CODE_ERROR_BAD_REQUEST

    if "" in [firstname, lastname, email]:
        return jsonify({'error': 'Empty parameter'}), HTTP_CODE_ERROR_BAD_REQUEST

    if re.match("^[a-zA-ZäÄöÖüÜ ,.'-]+$", firstname) is None or re.match("^[a-zA-ZäÄöÖüÜ ,.'-]+$", lastname) is None:
        return jsonify({'error': 'Firstname and/or lastname must contain only alphanumeric characters'}), HTTP_CODE_ERROR_BAD_REQUEST

    if firstname is not None:
        user_inst.firstnameUser = firstname
    if lastname is not None:
        user_inst.lastnameUser = lastname
    if email is not None:
        user_inst.emailUser = email

    return jsonify({'status': 'changed'}), HTTP_CODE_OK


@BP.route('', methods=['POST'])
@db_session_dec
def user_post(session):
    """
    Handles POST for resource <base>/api/users .
    :return: "{'status': 'User registered'}", 200
    """
    username = request.headers.get('username', default=None)
    firstname = request.headers.get('firstname', default=None)
    lastname = request.headers.get('lastname', default=None)
    email = request.headers.get('email', default=None)
    auth_token = request.headers.get('authToken', default=None)

    if None in [username, firstname, lastname, email, auth_token]:
        return jsonify({'error': 'Missing parameter'}), HTTP_CODE_ERROR_BAD_REQUEST

    if "" in [username, firstname, lastname, email, auth_token]:
        return jsonify({'error': "Empty parameter"}), HTTP_CODE_ERROR_BAD_REQUEST

    if re.match("^[a-zA-ZäÄöÖüÜ ,.'-]+$", firstname) is None or re.match("^[a-zA-ZäÄöÖüÜ ,.'-]+$", lastname) is None:
        return jsonify({'error': 'Firstname and/or lastname must contain only alphanumeric characters'}), HTTP_CODE_ERROR_BAD_REQUEST

    acc = WEB3.eth.account.create()

    try:
        shortened_token = BlockstackAuth.short_jwt(auth_token)
        username_token = BlockstackAuth.get_username_from_token(shortened_token)
        if username_token != username:
            return jsonify({'error': 'username in token doesnt match username'}), HTTP_CODE_ERROR_BAD_REQUEST

        res = session.query(User).filter(User.usernameUser == username).one_or_none()
        if res is not None:
            return jsonify({'status': 'User is already registered'}), HTTP_CODE_ERROR_BAD_REQUEST

        user_inst = User(usernameUser=username,
                         firstnameUser=firstname,
                         lastnameUser=lastname,
                         emailUser=email,
                         authToken=shortened_token,
                         publickeyUser=acc.address,
                         privatekeyUser=acc.key)
    except (KeyError, ValueError, DecodeError):  # jwt decode errors
        return jsonify({'status': 'Invalid JWT'}), HTTP_CODE_ERROR_BAD_REQUEST

    session.add(user_inst)
    session.commit()
    return jsonify({'status': 'User registered'}), HTTP_CODE_CREATED
