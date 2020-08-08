"""Institution Resource."""
from base64 import b64decode
import validators
from flask import Blueprint, request, jsonify
from geopy import distance

from backend.database.model import Institution, User
from backend.resources.helpers import auth_user, check_params_int, check_params_float, db_session_dec
from backend.smart_contracts.web3_voucher import voucher_constructor, voucher_constructor_check

BP = Blueprint('institutions', __name__, url_prefix='/api/institutions')  # set blueprint name and resource path

HTTP_CODE_CREATED = 201
HTTP_CODE_ERROR_BAD_REQUEST = 400
HTTP_CODE_ERROR_FORBIDDEN = 403
HTTP_CODE_ERROR_NOT_FOUND = 404

@BP.route('', methods=['GET'])
@db_session_dec
def institutions_get(session):
    """
    Handles GET for resource <base>/api/institutions .

    :return: json data of institutions
    """
    id_institution = request.args.get('id')
    radius = request.args.get('radius')
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    name_institution = request.args.get('name')
    has_vouchers = request.args.get('has_vouchers')
    username = request.args.get('username')

    try:
        check_params_int([id_institution, radius, has_vouchers])
        # pylint: disable=unbalanced-tuple-unpacking
        radius, latitude, longitude = check_params_float([radius, latitude, longitude])
    except ValueError:
        return jsonify({"error": "bad argument"}), HTTP_CODE_ERROR_BAD_REQUEST
    if None in [radius, latitude, longitude] and any([radius, latitude, longitude]):
        return jsonify({"error": "bad geo argument"}), HTTP_CODE_ERROR_BAD_REQUEST

    results = session.query(Institution).join(Institution.user)

    json_data = []

    if username:
        results = results.filter(User.usernameUser == username)
    if id_institution:
        results = results.filter(Institution.idInstitution == id_institution)
    if name_institution:
        results = results.filter(Institution.nameInstitution.ilike("%" + name_institution + "%"))
    if has_vouchers is not None:
        if int(has_vouchers) == 1:
            results = results.filter(Institution.vouchers.any())
        else:
            results = results.filter(~Institution.vouchers.any())

    for result in results:
        result: Institution = result
        if radius and latitude and longitude and \
                distance.distance((latitude, longitude), (result.latitude, result.longitude)).km > radius:
            continue
        json_data.append({
            "id": result.idInstitution,
            "name": result.nameInstitution,
            "webpage": result.webpageInstitution,
            "address": result.addressInstitution,
            "picturePath": result.picPathInstitution,
            "longitude": result.longitude,
            "latitude": result.latitude,
            "publickey": result.publickeyInstitution,
            "description": result.descriptionInstitution,
            "short": result.shortDescription,
            "username": result.user.usernameUser,
        })

    return jsonify(json_data)


@BP.route('', methods=['POST'])
@auth_user
@db_session_dec
def institutions_post(session, user_inst):  # pylint:disable=unused-argument
    """
    Handles POST for resource <base>/api/institutions .
    :return: json response
    """
    name = request.headers.get('name')
    webpage = request.headers.get('webpage')
    address = request.headers.get('address')
    username = request.headers.get('username')
    publickey = request.headers.get('publickey')
    description = request.headers.get('description')
    short = request.headers.get('short')
    latitude = request.headers.get('latitude')
    longitude = request.headers.get('longitude')

    if not user_inst.group == "support":
        return jsonify({'error': 'Forbidden'}), HTTP_CODE_ERROR_FORBIDDEN
    if None in [name, address, latitude, longitude, publickey]:
        return jsonify({'error': 'Missing parameter'}), HTTP_CODE_ERROR_BAD_REQUEST

    try:
        # pylint: disable=unbalanced-tuple-unpacking
        latitude, longitude = check_params_float([latitude, longitude])
    except ValueError:
        return jsonify({"error": "bad argument"}), HTTP_CODE_ERROR_BAD_REQUEST

    try:
        description = b64decode(description).decode("latin-1")
    except TypeError:
        return jsonify({"error": "bad base64 encoding"}), HTTP_CODE_ERROR_BAD_REQUEST

    if webpage is not None and not validators.url(webpage):
        return jsonify({'error': 'webpage is not a valid url'}), HTTP_CODE_ERROR_BAD_REQUEST

    owner_inst: User = session.query(User).filter(User.usernameUser == username).one_or_none()
    if owner_inst is None:
        return jsonify({'error': 'username not found'}), HTTP_CODE_ERROR_BAD_REQUEST

    # check if name is already taken
    if session.query(Institution).filter(Institution.nameInstitution == name).first():
        return jsonify({'error': 'name already exists'}), HTTP_CODE_ERROR_BAD_REQUEST

    try:
        vouch_check = voucher_constructor_check(publickey)
        if vouch_check:
            return jsonify({'error': 'milestone error: ' + vouch_check}), HTTP_CODE_ERROR_BAD_REQUEST

        sc_address = voucher_constructor(publickey)

        session.add(
            Institution(
                nameInstitution=name,
                webpageInstitution=webpage,
                addressInstitution=address,
                publickeyInstitution=publickey,
                descriptionInstitution=description,
                latitude=latitude,
                longitude=longitude,
                scAddress=sc_address,
                user=owner_inst,
                shortDescription=short
            ))
        session.commit()
        return jsonify({'status': 'Institution wurde erstellt'}), HTTP_CODE_CREATED
    finally:
        session.rollback()
        session.close()


@BP.route('', methods=['PATCH'])
@auth_user
@db_session_dec
def institutions_patch(session, user_inst):  # pylint:disable=too-many-branches
    """
    Handles PATCH for resource <base>/api/institutions .
    :return: json response
    """
    institution_id = request.headers.get('id')
    name = request.headers.get('name')
    webpage = request.headers.get('webpage')
    address = request.headers.get('address')
    description = request.headers.get('description')
    short = request.headers.get('short')
    latitude = request.headers.get('latitude')
    longitude = request.headers.get('longitude')

    if institution_id is None:
        return jsonify({'error': 'Missing parameter'}), HTTP_CODE_ERROR_BAD_REQUEST

    try:
        check_params_int([institution_id])
        check_params_float([latitude, longitude])
    except ValueError:
        return jsonify({"error": "bad argument"}), HTTP_CODE_ERROR_BAD_REQUEST
    if None in [latitude, longitude] and any([latitude, longitude]):
        return jsonify({"error": "bad geo argument"}), HTTP_CODE_ERROR_BAD_REQUEST

    try:
        if name:  # check if name is already taken
            if session.query(Institution).filter(Institution.nameInstitution == name).one_or_none():
                return jsonify({'error': 'name already exists'}), HTTP_CODE_ERROR_BAD_REQUEST

        institution = session.query(Institution).get(institution_id)
        if institution is None:
            return jsonify({'error': 'Institution does not exist'}), HTTP_CODE_ERROR_NOT_FOUND

        # check user permission
        owner = session.query(Institution)
        owner = owner.filter(Institution.user == user_inst, Institution.idInstitution == institution_id).one_or_none()

        if owner is None:
            return jsonify({'error': 'no permission'}), HTTP_CODE_ERROR_FORBIDDEN

        if name:
            institution.nameInstitution = name
        if address:
            institution.addressInstitution = address
        if webpage:
            institution.webpageInstitution = webpage
        if description:
            try:
                description = b64decode(description).decode("latin-1")
            except TypeError:
                return jsonify({"error": "bad base64 encoding"}), HTTP_CODE_ERROR_BAD_REQUEST
            institution.descriptionInstitution = description
        if short:
            institution.shortDescription = short
        if latitude and longitude:
            institution.latitude = latitude
            institution.longitude = longitude

        session.commit()
        return jsonify({'status': 'Institution wurde bearbeitet'}), HTTP_CODE_CREATED
    finally:
        session.rollback()
        session.close()
