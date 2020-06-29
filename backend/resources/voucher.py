"""Voucher Resource."""
import configparser
import json

from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from sqlalchemy.orm.exc import NoResultFound

from web3.exceptions import InvalidAddress

from backend.smart_contracts.web3 import WEB3

from backend.database.db import DB_SESSION
from backend.database.model import Voucher, VoucherUser, User, Institution
from backend.resources.helpers import auth_user, check_params_int

BP = Blueprint('voucher', __name__, url_prefix='/api/vouchers')


@BP.route('/institution', methods=['GET'])
def voucher_get():
    """
    Handles GET for resource <base>/api/voucher/institution .
    :return: json data of projects
    """
    id_voucher = request.args.get('id')
    id_institution = request.args.get('idInstitution')
    available = request.args.get('available')

    try:
        check_params_int([id_voucher, id_institution, available])
    except ValueError:
        return jsonify({"error": "bad argument"}), 400

    session = DB_SESSION()
    results = session.query(Voucher)

    if id_voucher is not None:
        results = results.filter(Voucher.idVoucher == id_voucher)
    if id_institution is not None:
        results = results.filter(Voucher.institution_id == id_institution)
    if available is not None:
        results = results.filter(Voucher.available.is_(bool(int(available))))

    json_data = []
    for voucher in results:
        json_data.append({
            'id': voucher.idVoucher,
            'amount': len(voucher.users),
            'institutionid': voucher.institution_id,
            'institutionName': voucher.institution.nameInstitution,
            'subject': voucher.descriptionVoucher,
            'title': voucher.titleVoucher,
            'validTime': voucher.validTime,
            'available': voucher.available,
            'price': voucher.priceVoucher,
        })

    return jsonify(json_data), 200


@BP.route('/user', methods=['POST'])
@auth_user
def voucher_post(user):
    """
    Handles POST for resource <base>/api/voucher/user .
    :return: json data of projects
    """
    id_voucher = request.headers.get('idVoucher')
    if not id_voucher:
        return jsonify({'error': 'missing id'}), 400
    try:
        check_params_int([id_voucher])
    except ValueError:
        return jsonify({"error": "bad argument"}), 400

    session = DB_SESSION()

    try:
        voucher = session.query(Voucher).filter(Voucher.idVoucher == id_voucher).one()
        balance = 9e19  # WEB3.eth.getBalance(user.publickeyUser)  # ToDo: Add balance (to tests)

        if balance < voucher.priceVoucher:
            return jsonify({'error': 'not enough balance'}), 406
        if not voucher.available:
            return jsonify({'error': 'voucher not available'}), 406

        association = VoucherUser(usedVoucher=False,
                                  expires_unixtime=(datetime.now() + timedelta(0, 2 * 31536000)))
        association.voucher = voucher
        association.user = user

        w3 = WEB3

        user_priv = user.privatekeyUser

        inst = session.query(Institution).filter(Institution.idInstitution == voucher.institution_id)
        inst_wllt = inst.one().addressInstitution

        a1 = "0x1ba1D6bCDec9b97C001CbAcBfE0Aab3279b72fd1"
        a2 = "0x7FFbF8F9321B6D9c8f60eD6fa58c391499683377"

        a1p = "70b9a100cc3df02a61add624ab1b3d98aea20b1784a31fa3175093cec4a8941e"

        nonce = w3.eth.getTransactionCount(a1)
        tx_trans = {
            'nonce': nonce,
            'to': a2,
            'value': voucher.priceVoucher,
            'gas': 200000,
            'gasPrice': w3.toWei('50', 'gwei')
        }
        signed_tx_trans = w3.eth.account.signTransaction(tx_trans, a1p) 
        w3.eth.sendRawTransaction(signed_tx_trans.rawTransaction)

        CFG_PARSER: configparser.ConfigParser = configparser.ConfigParser()
        CFG_PARSER.read("backend_config.ini")

        sc_add = w3.toChecksumAddress(CFG_PARSER["Voucher"]["ADDRESS"])
        sc_abi = json.loads(CFG_PARSER["Voucher"]["ABI"])

        voucher_sc = w3.eth.contract(address=sc_add, abi=sc_abi)

        nonce = w3.eth.getTransactionCount(a1)
        tx_add = voucher_sc.functions.addVoucher(a1, w3.toBytes(text=voucher.titleVoucher), 666)\
            .buildTransaction({'nonce': nonce})
        signed_tx_add = w3.eth.account.signTransaction(tx_add, a1p)
        
        w3.eth.sendRawTransaction(signed_tx_add.rawTransaction)

        session.add(voucher)
        session.add(association)
        session.commit()
    except InvalidAddress:
        return jsonify({'error': 'given publickey is not valid'}), 400
    except NoResultFound:
        return jsonify({'error': 'Voucher doesnt exist'}), 404

    return jsonify({'status': 'voucher bought'}), 200


@BP.route('/user', methods=['DELETE'])
@auth_user
def voucher_delete_user(user_inst):
    """
    Handles DELETE for resource <base>/api/voucher/user .
    :return: json data of projects
    """
    id_voucheruser = request.headers.get('id')

    if not id_voucheruser:
        return jsonify({'error': 'missing id'}), 400
    try:
        check_params_int([id_voucheruser])
    except ValueError:
        return jsonify({"error": "bad argument"}), 400

    session = DB_SESSION()
    voucher = session.query(VoucherUser)
    try:
        voucher = voucher.filter(VoucherUser.idVoucherUser == id_voucheruser).filter(
            VoucherUser.id_user == user_inst.idUser).one()
    except NoResultFound:
        return jsonify({'error': 'No voucher found'}), 404

    voucher.usedVoucher = True
    session.commit()

    return jsonify({'status': 'Gutschein wurde eingelöst'}), 201


@BP.route('/user', methods=['GET'])
def voucher_get_user():
    """
    Handles GET for resource <base>/api/voucher/user .
    :return: json data of projects
    """
    id_voucheruser = request.args.get('id')
    id_voucher = request.args.get('idVoucher')
    id_user = request.args.get('idUser')
    id_institution = request.args.get('idInstitution')
    used = request.args.get('used')
    expired = request.args.get('expired')

    try:
        check_params_int([id_voucher, id_user, id_institution, used, expired])
    except ValueError:
        return jsonify({"error": "bad argument"}), 400

    session = DB_SESSION()

    results = session.query(Voucher, VoucherUser).join(Voucher, VoucherUser.id_voucher == Voucher.idVoucher)

    if id_voucheruser is not None:
        results = results.filter(VoucherUser.idVoucherUser == id_voucheruser)
    if id_voucher is not None:
        results = results.filter(Voucher.idVoucher == id_voucher)
    if id_user is not None:
        results = results.filter(VoucherUser.id_user == id_user)
    if id_institution is not None:
        results = results.filter(Voucher.institution_id == id_institution)
    if used is not None:
        results = results.filter(VoucherUser.usedVoucher.is_(used))
    if expired is not None:
        if int(expired) >= 1:
            results = results.filter(VoucherUser.expires_unixtime < datetime.now())
        else:
            results = results.filter(VoucherUser.expires_unixtime >= datetime.now())

    json_data = []
    for vouch, vuser in results:
        json_data.append({
            "id": vuser.idVoucherUser,
            "userid": vuser.id_user,
            "idvoucher": vuser.id_voucher,
            "idinstitution": vouch.institution_id,
            "titel": vouch.titleVoucher,
            "description": vouch.descriptionVoucher,
            "used": vuser.usedVoucher,
            "untilTime": vuser.expires_unixtime.timestamp(),
            "price": vouch.priceVoucher,
        })

    return jsonify(json_data), 200
