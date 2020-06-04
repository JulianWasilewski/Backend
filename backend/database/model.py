"""Defines the (declarative_base) model."""
from datetime import datetime
from typing import List

from sqlalchemy import Column, ForeignKey, Integer, VARCHAR, BINARY, TIMESTAMP, Table, BOOLEAN
from sqlalchemy.ext.declarative import declarative_base, DeclarativeMeta
from sqlalchemy.orm import relationship

BASE: DeclarativeMeta = declarative_base()


class Project(BASE):
    __tablename__ = 'Project'
    idProject = Column(Integer, primary_key=True)
    nameProject = Column(VARCHAR(256))
    webpageProject = Column(VARCHAR(256))

    smartcontract_id = Column(Integer, ForeignKey('SmartContract.idSmartContract'))
    smartcontract = relationship("SmartContract", back_populates="projects")

    institution_id = Column(Integer, ForeignKey('Institution.idInstitution'))
    institution = relationship("Institution", back_populates="projects")

    milestones = relationship("Milestone", back_populates="project")


class SmartContract(BASE):
    __tablename__ = 'SmartContract'
    idSmartContract = Column(Integer, primary_key=True)
    blockchainAddrSmartContract = Column(BINARY(20))

    projects = relationship("Project", back_populates="smartcontract")
    institutions = relationship("Institution", back_populates="smartcontract")
    transactions = relationship("Transaction", back_populates="smartcontract")


class Milestone(BASE):
    __tablename__ = 'Milestone'
    idMilestone = Column(Integer, primary_key=True)
    goalMilestone = Column(Integer)
    requiredVotesMilestone = Column(Integer)
    currentVotesMilestone = Column(Integer)
    untilBlockMilestone = Column(Integer)

    project_id = Column(Integer, ForeignKey('Project.idProject'))
    project = relationship("Project", back_populates="milestones")

    donations = relationship("Donation", back_populates="")


class Institution(BASE):
    __tablename__ = 'Institution'
    idInstitution = Column(Integer, primary_key=True)
    nameInstitution = Column(VARCHAR(256))
    webpageInstitution = Column(VARCHAR(256))

    projects = relationship("Project", back_populates="institution")

    smartcontract_id = Column(Integer, ForeignKey('SmartContract.idSmartContract'))
    smartcontract = relationship("SmartContract", back_populates="institutions")

    vouchers = relationship("Voucher", back_populates="institution")


VOUCHER_USER_TABLE = Table("VoucherUser", BASE.metadata,
                           Column("idUser", Integer, ForeignKey("User.idUser"), primary_key=True),
                           Column("idVoucher", Integer, ForeignKey("Voucher.idVoucher"), primary_key=True)
                           )


class Voucher(BASE):
    __tablename__ = 'Voucher'
    idVoucher = Column(Integer, primary_key=True)
    titleVoucher = Column(VARCHAR(32))
    descriptionVoucher = Column(VARCHAR(1024))
    usedVoucher = Column(BOOLEAN)
    untilBlockVoucher = Column(Integer)

    institution_id = Column(Integer, ForeignKey('Institution.idInstitution'))
    institution = relationship("Institution", back_populates="vouchers")

    users = relationship("User", secondary=VOUCHER_USER_TABLE, back_populates="vouchers")


class User(BASE):
    __tablename__ = 'User'
    idUser = Column(Integer, primary_key=True)
    usernameUser = Column(VARCHAR(45))
    firstnameUser = Column(VARCHAR(45))
    lastnameUser = Column(VARCHAR(45))
    emailUser = Column(VARCHAR(45))
    publickeyUser = Column(BINARY(64))
    privatekeyUser = Column(BINARY(128))
    authToken = Column(VARCHAR(2048))

    donations = relationship("Donation", back_populates="user")

    transactions = relationship("Transaction", back_populates="user")

    vouchers = relationship("Voucher", secondary=VOUCHER_USER_TABLE, back_populates="users")


class Donation(BASE):
    __tablename__ = 'Donation'
    idDonation = Column(Integer, primary_key=True)
    amountDonation = Column(Integer)

    user_id = Column(Integer, ForeignKey('User.idUser'))
    user = relationship("User", back_populates="donations")

    milestone_id = Column(Integer, ForeignKey('Milestone.idMilestone'))
    milestone = relationship("Milestone", back_populates="donations")


class Transaction(BASE):
    __tablename__ = 'Transaction'
    idTransaction = Column(Integer, primary_key=True)
    dateTransaction = Column(TIMESTAMP)

    smartcontract_id = Column(Integer, ForeignKey('SmartContract.idSmartContract'))
    smartcontract = relationship("SmartContract", back_populates="transactions")

    user_id = Column(Integer, ForeignKey('User.idUser'))
    user = relationship("User", back_populates="transactions")


# sw2020testuser1.id.blockstack
__TOKEN_1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiIyNGE1OTFkNS1lOGJiLTQwMzYtYWE0Ni1hNzg5MjU2ZDVjZDYiLCJp" \
          "YXQiOjE1OTEyMjUyMzIsImV4cCI6MTU5MzgxNzIzMiwiaXNzIjoiZGlkOmJ0Yy1hZGRyOjE0Z1N4eFhZdzlXbTNoYWoxaGVKYXQ1ZGd" \
          "peHF0YVJ3a3MiLCJwcml2YXRlX2tleSI6IjdiMjI2OTc2MjIzYTIyNjEzMDMwMzA2NjY0MzAzNDY2NjIzNzM0MzQzNzM5MzM2NTM2Mz" \
          "A2MTY1NjYzMDM4MzE2NDYzNjMzMzY1MzEzNDIyMmMyMjY1NzA2ODY1NmQ2NTcyNjE2YzUwNGIyMjNhMjIzMDMyNjYzNDYxMzMzMTYyM" \
          "zA2NDY1NjY2MjM4MzkzNTM4MzY2NjY1NjIzMzM5MzY2MTYzMzE2MzYzNjYzMzYzMzg2NjY1NjM2MzM4NjM2NjMwNjMzNTM2MzMzODYx" \
          "MzEzMDYzMzAzNDM4NjYzOTM1MzEzMzMwMzY2NTY1MzEzNzY1MzgyMjJjMjI2MzY5NzA2ODY1NzI1NDY1Nzg3NDIyM2EyMjM1MzAzOTM" \
          "4MzMzOTM5MzQ2MzY2NjMzODMyMzQ2MjY2Mzc2MjYyMzczNzMwMzM2MzM3NjM2NTMzMzU2NDYzNjI2NDYyMzUzMzM0NjU2NTYzNjQ2Mz" \
          "MyNjIzODMwNjEzNzYzNjQzOTM0MzU2NDYzNjMzOTM1MzkzOTM0MzQzNDY1MzY2MzM4MzY2MzMyMzU2NjM4NjM2MjM1NjEzMjMxMzkzM" \
          "zMzNjEzOTM5MzMzODYxMzY2MzMxNjI2NDMwMzg2NTM1MzkzMTM2NjI2MjMxNjY2NTM2MzIzNjYzNjYzNDY2NjM2NDMyMzEzMjMzNjM2" \
          "MTM1MzkzNTYyMzkzNjMxMzAzNzMyMzgzMTYzMzkzNTYxMzc2MTY1MzAzMzY2NjIzNjMwNjM2MjY2MzE2MjMyMzIzNTY0MzUzMTMzMzA" \
          "zNzMwMjIyYzIyNmQ2MTYzMjIzYTIyNjM2MzY2MzQ2NTYxNjQ2NTM4MzMzMTM0MzA2MzMxMzAzNjM0MzEzMDMyNjI2NTMyMzA2MzY1Mz" \
          "M2NDY0MzEzMDYyMzM2NDM3NjIzMjMxMzg2MjM4NjQzODM3MzgzNzYzMzk2NTY0Mzc2NDYxNjIzMDYzMzQzNTM5MzAzMDM3MzkyMjJjM" \
          "jI3NzYxNzM1Mzc0NzI2OTZlNjcyMjNhNzQ3Mjc1NjU3ZCIsInB1YmxpY19rZXlzIjpbIjAzOWJlYzg2OTEwZWJmZWYwZThmYTdiYTY5" \
          "NDUxZTVmOWM0NTU2OGZkMWEyZjgwNDkzMzYxYWUzNTM4YzY3ZjdiYiJdLCJwcm9maWxlIjpudWxsLCJ1c2VybmFtZSI6InN3MjAyMHR" \
          "lc3R1c2VyMS5pZC5ibG9ja3N0YWNrIiwiY29yZV90b2tlbiI6bnVsbCwiZW1haWwiOm51bGwsInByb2ZpbGVfdXJsIjoiaHR0cHM6Ly" \
          "9nYWlhLmJsb2Nrc3RhY2sub3JnL2h1Yi8xNGdTeHhYWXc5V20zaGFqMWhlSmF0NWRnaXhxdGFSd2tzL3Byb2ZpbGUuanNvbiIsImh1Y" \
          "lVybCI6Imh0dHBzOi8vaHViLmJsb2Nrc3RhY2sub3JnIiwiYmxvY2tzdGFja0FQSVVybCI6Imh0dHBzOi8vY29yZS5ibG9ja3N0YWNr" \
          "Lm9yZyIsImFzc29jaWF0aW9uVG9rZW4iOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUpqYUdsc1pGUnZ" \
          "RWE56YjJOcFlYUmxJam9pTURJME1tRXpOR0ZpTTJFeFpUUmtabU5pTXpjd056QTFZelUyTVdNelpEVXdPV0prTURneU16Vm1NVGRpWm" \
          "pReFpEZzFPRFJrWkRNM01EZGpaVEkyWkdVeUlpd2lhWE56SWpvaU1ETTVZbVZqT0RZNU1UQmxZbVpsWmpCbE9HWmhOMkpoTmprME5UR" \
          "mxOV1k1WXpRMU5UWTRabVF4WVRKbU9EQTBPVE16TmpGaFpUTTFNemhqTmpkbU4ySmlJaXdpWlhod0lqb3hOakl5TnpZeE1qTXlMakF5" \
          "TENKcFlYUWlPakUxT1RFeU1qVXlNekl1TURJc0luTmhiSFFpT2lKaFl6RTFaR1EwWWpKbE5HRTJOVFkwT0Roa05qUXhZVFExTm1NMll" \
          "qVTVOeUo5LkRXbl9kNVBmQ0NxVmRnMUV2Rl9velNULXlCRFcwcGFVWXFwZGYxbjZ1WGpZY0xOUmUzQW1FSGtDSTZLWS0xTVNQWG05SU" \
          "ljZmlZb1Mtd0JpWXV4d05nIiwidmVyc2lvbiI6IjEuMy4xIn0.PljXRkEKvUHIZJwll4CVBgGfVrfSaxltRo47dHEiJHmCVuYwGiTii" \
          "hZShJLjS5URoh_TUpdLMlH1ookLjF4Ehw"

# sw2020testuser2.id.blockstack
__TOKEN_2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiIxZjJiYzcyNy03Y2ZhLTQ5NDEtOTk4ZC03YjIyMGEwOTg2NmYiLCJp" \
          "YXQiOjE1OTEyMjU0OTYsImV4cCI6MTU5MzgxNzQ5NiwiaXNzIjoiZGlkOmJ0Yy1hZGRyOjFIMlQxY0Rmd3lZZFlra1pFUkhmQUh4SkJ" \
          "xaDNieTlWd2kiLCJwcml2YXRlX2tleSI6IjdiMjI2OTc2MjIzYTIyMzAzMTMxMzIzNTY0MzMzMzM1MzMzNDYxNjYzMDM0MzE2NTM1Mz" \
          "czNDMyMzczMjMwNjU2MzM0Mzk2MzMwMzY2NjIyMmMyMjY1NzA2ODY1NmQ2NTcyNjE2YzUwNGIyMjNhMjIzMDMzMzQ2MzM4MzgzNzM4M" \
          "zczNTM1MzAzMjM2MzI2MTM3MzI2NjMyNjE2MzY0MzUzMTMxNjY2NjM5MzczNTM3NjMzMTYzNjU2NDM3NjUzNjY2NjU2MjMzNjYzOTMy" \
          "MzQzNTY0MzQ2NjMxNjIzMjYxMzE2MTM0Mzk2MzM0MzMzNjMxMzAyMjJjMjI2MzY5NzA2ODY1NzI1NDY1Nzg3NDIyM2EyMjM5NjYzNzY" \
          "0MzMzNTM0NjQ2NTM3MzAzNjYzMzM2NjY0MzMzODM0MzAzNTY2MzUzOTY1NjMzODM5MzAzMTM3MzIzMjMwMzE2NDY2MzEzMTYzMzc2NT" \
          "M4MzczMzM4NjUzNzY1MzA2NjMyNjUzNzY1MzM2MjM1NjQzOTMzNjE2MTMxNjQ2MzYyMzgzNDYzMzA2NTM2NjY2NDYyNjY2MTM2NjIzM" \
          "DMyNjEzNTMzMzYzMTY2NjYzODYzNjUzMjYxNjQ2MTYyNjYzMjM5MzM2NTMzMzEzOTM0MzQzOTM5NjM2NDYzNjQzNDMxNjQzMjY2Mzkz" \
          "MjM4MzA2MzY1MzEzNDY2NjEzOTYzNjE2MzY0NjYzNzM1NjUzNzMwNjM2NjYzNjY2MzYxNjQzNDY1MzgzMjM4NjQzNjMwMzAzNzM0NjQ" \
          "2MTM4MjIyYzIyNmQ2MTYzMjIzYTIyMzczMDMwNjMzMjY1MzgzMjMzMzE2MzM2NjIzNTYzMzM2MjYxNjIzMTYzMzczNTM2MzUzNjM1Nj" \
          "E2NDYzMzU2MjYxNjYzMzMxMzczODY0MzY2MTYxMzEzNTM4MzUzNjY2MzkzNDM3MzA2MzYzNjM2MzY2NjYzOTMwMzUzNjM2NjMyMjJjM" \
          "jI3NzYxNzM1Mzc0NzI2OTZlNjcyMjNhNzQ3Mjc1NjU3ZCIsInB1YmxpY19rZXlzIjpbIjAzODM0YTYxMjc1NzQ3OGIyOWEwZTRmMDE1" \
          "N2IyNzBhOTc5NTM3NzUxNWE2MmQwYTYzYTI1ZDU2MGYwODE4ZTk1YiJdLCJwcm9maWxlIjpudWxsLCJ1c2VybmFtZSI6InN3MjAyMHR" \
          "lc3R1c2VyMi5pZC5ibG9ja3N0YWNrIiwiY29yZV90b2tlbiI6bnVsbCwiZW1haWwiOm51bGwsInByb2ZpbGVfdXJsIjoiaHR0cHM6Ly" \
          "9nYWlhLmJsb2Nrc3RhY2sub3JnL2h1Yi8xSDJUMWNEZnd5WWRZa2taRVJIZkFIeEpCcWgzYnk5VndpL3Byb2ZpbGUuanNvbiIsImh1Y" \
          "lVybCI6Imh0dHBzOi8vaHViLmJsb2Nrc3RhY2sub3JnIiwiYmxvY2tzdGFja0FQSVVybCI6Imh0dHBzOi8vY29yZS5ibG9ja3N0YWNr" \
          "Lm9yZyIsImFzc29jaWF0aW9uVG9rZW4iOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUpqYUdsc1pGUnZ" \
          "RWE56YjJOcFlYUmxJam9pTURNd1lUY3dPV1E1WVRFMk1tUXdaV0kxTmpsbFltRTFZbVExTUdNeE0yWTJOak00T0RFNE9UbG1OV1ZrT1" \
          "RBMVlXUmxNamcwWm1JNVpXUTFOemRpTnpZM0lpd2lhWE56SWpvaU1ETTRNelJoTmpFeU56VTNORGM0WWpJNVlUQmxOR1l3TVRVM1lqS" \
          "TNNR0U1TnprMU16YzNOVEUxWVRZeVpEQmhOak5oTWpWa05UWXdaakE0TVRobE9UVmlJaXdpWlhod0lqb3hOakl5TnpZeE5EazJMak0z" \
          "TVN3aWFXRjBJam94TlRreE1qSTFORGsyTGpNM01Td2ljMkZzZENJNklqY3paR0ZqTVdZMU9UVXhZbU0wWmpNeVl6UTBNamN5TXpKall" \
          "UUmhORGN4SW4wLkxvZlFacFlSaktxd0tuOXQ2VFNEdGVlUUxWSlYyZzA1Nm9NVXBVSEtQUXUxSGg4TGlUU29JaUNBV05qbV9idTJhYm" \
          "NVLThla2dpUU5NUy15VUVVRUVBIiwidmVyc2lvbiI6IjEuMy4xIn0.BhUkt3dAOPkO9xiHAflynVuAtmyoSVGb4TUxFlNhL-6Mc4sVw" \
          "N1yiP2_cyxJlzKBeYumqtNLnWTmlOV8XhrtXQ"


def add_sample_data(db_session):  # pylint:disable=too-many-statements
    """
    Adds some sample data.

    :param db_session: DB_SESSION object
    :return: -
    """
    session = db_session()

    smartcontracts: List[SmartContract] = [
        SmartContract(idSmartContract=1,
                      blockchainAddrSmartContract=bytes("666", encoding="utf-8")),
        SmartContract(idSmartContract=2,
                      blockchainAddrSmartContract=bytes("1337", encoding="utf-8")),
    ]

    users: List[User] = [
        User(idUser=1,
             usernameUser="LoetkolbenLudwig",
             firstnameUser="Ludwig", lastnameUser="Loetkolben",
             emailUser="ll@swp.de",
             publickeyUser=bytes("4242424242", encoding="utf-8"),
             privatekeyUser=bytes("2424242424", encoding="utf-8")),
        User(idUser=2,
             usernameUser="MSDOSManfred",
             firstnameUser="Manfred", lastnameUser="MSDOS",
             emailUser="msdosm@swp.de",
             publickeyUser=bytes("133713371337", encoding="utf-8"),
             privatekeyUser=bytes("733173317331", encoding="utf-8")),
        User(idUser=3,
             usernameUser="HardwareHansPeter",
             firstnameUser="HansPeter", lastnameUser="Hardware",
             emailUser="hwhp@swp.de",
             publickeyUser=bytes("6668866688", encoding="utf-8"),
             privatekeyUser=bytes("8866688666", encoding="utf-8")),
        User(idUser=4,
             usernameUser="BIOSBernhard",
             firstnameUser="Bernhard", lastnameUser="BIOS",
             emailUser="biosb@swp.de",
             publickeyUser=bytes("1003310033", encoding="utf-8"),
             privatekeyUser=bytes("3300133001", encoding="utf-8")),
        User(idUser=5,
             usernameUser="OdinsonThor",
             firstnameUser="Thor", lastnameUser="Odinson",
             emailUser="ot@swp.de",
             publickeyUser=bytes("268110268110", encoding="utf-8"),
             privatekeyUser=bytes("011862011862", encoding="utf-8")),
        User(idUser=6,
             usernameUser="sw2020testuser1.id.blockstack",
             firstnameUser="testuser1", lastnameUser="sw2020",
             emailUser="testuser1@example.com",
             publickeyUser=bytes("14234132", encoding="utf-8"),
             privatekeyUser=bytes("2344322134", encoding="utf-8"),
             authToken=__TOKEN_1),
        User(idUser=7,
             usernameUser="sw2020testuser2.id.blockstack",
             firstnameUser="testuser2", lastnameUser="sw2020",
             emailUser="testuser2@example.com",
             publickeyUser=bytes("14234132", encoding="utf-8"),
             privatekeyUser=bytes("2344322134", encoding="utf-8"),
             authToken=__TOKEN_2),
    ]

    institutions: List[Institution] = [
        Institution(idInstitution=1,
                    nameInstitution="MSGraphic",
                    webpageInstitution="www.msgraphic.com"),
        Institution(idInstitution=2,
                    nameInstitution="SWP",
                    webpageInstitution="www.swp.com"),
        Institution(idInstitution=3,
                    nameInstitution="Asgard Inc.",
                    webpageInstitution="www.asgard.as"),
        Institution(idInstitution=4,
                    nameInstitution="Blackhole",
                    webpageInstitution="127.0.0.1"),
    ]
    # set SmartContract to Institution
    institutions[0].smartcontract = smartcontracts[0]
    institutions[1].smartcontract = smartcontracts[0]
    institutions[2].smartcontract = smartcontracts[0]
    institutions[3].smartcontract = smartcontracts[0]

    projects: List[Project] = [
        Project(idProject=1,
                nameProject="Computer malt Bild",
                webpageProject="www.cmb.de"),
        Project(idProject=2,
                nameProject="Rangaroek verteidigen",
                webpageProject="www.asgard.as"),
        Project(idProject=3,
                nameProject="Softwareprojekt 2020",
                webpageProject="www.swp.de"),
    ]
    # set SmartContract to Project
    projects[0].smartcontract = smartcontracts[1]
    projects[1].smartcontract = smartcontracts[1]
    projects[2].smartcontract = smartcontracts[1]
    # set Institution to Project
    projects[0].institution = institutions[0]
    projects[1].institution = institutions[2]
    projects[2].institution = institutions[2]

    milestones: List[Milestone] = [
        Milestone(idMilestone=1, goalMilestone=1000, requiredVotesMilestone=112, currentVotesMilestone=112,
                  untilBlockMilestone=600000),
        Milestone(idMilestone=2, goalMilestone=2000, requiredVotesMilestone=112, currentVotesMilestone=12,
                  untilBlockMilestone=1200000),
        Milestone(idMilestone=3, goalMilestone=3000, requiredVotesMilestone=112, currentVotesMilestone=0,
                  untilBlockMilestone=2400000),
        Milestone(idMilestone=4, goalMilestone=1000, requiredVotesMilestone=88, currentVotesMilestone=0,
                  untilBlockMilestone=121212121),
        Milestone(idMilestone=5, goalMilestone=2000, requiredVotesMilestone=88, currentVotesMilestone=12,
                  untilBlockMilestone=321123448),
        Milestone(idMilestone=6, goalMilestone=3000, requiredVotesMilestone=88, currentVotesMilestone=44,
                  untilBlockMilestone=654654832),
        Milestone(idMilestone=7, goalMilestone=5000, requiredVotesMilestone=666, currentVotesMilestone=400,
                  untilBlockMilestone=100000000),
    ]
    # set Project to Milestone
    milestones[0].project = projects[0]
    milestones[1].project = projects[0]
    milestones[2].project = projects[0]
    milestones[3].project = projects[1]
    milestones[4].project = projects[1]
    milestones[5].project = projects[2]
    milestones[6].project = projects[0]

    donations: List[Donation] = [
        Donation(idDonation=1, amountDonation=300),
        Donation(idDonation=2, amountDonation=200),
        Donation(idDonation=3, amountDonation=100),
        Donation(idDonation=4, amountDonation=400),
    ]
    # set Milestone to Donation
    donations[0].milestone = milestones[0]
    donations[1].milestone = milestones[1]
    donations[2].milestone = milestones[2]
    donations[3].milestone = milestones[3]
    # set User to Donation
    donations[0].user = users[0]
    donations[1].user = users[1]
    donations[2].user = users[2]
    donations[3].user = users[3]

    transactions: List[Transaction] = [
        Transaction(idTransaction=1, dateTransaction=datetime.now()),
        Transaction(idTransaction=2, dateTransaction=datetime.now()),
        Transaction(idTransaction=3, dateTransaction=datetime.now()),
        Transaction(idTransaction=4, dateTransaction=datetime.now()),
    ]
    # set smartcontract to transactions
    transactions[0].smartcontract = smartcontracts[0]
    transactions[1].smartcontract = smartcontracts[0]
    transactions[2].smartcontract = smartcontracts[0]
    transactions[3].smartcontract = smartcontracts[0]
    transactions[0].user = users[0]
    transactions[1].user = users[1]
    transactions[2].user = users[2]
    transactions[3].user = users[3]

    vouchers: List[Voucher] = [
        Voucher(idVoucher=1,
                titleVoucher="Von Computer gemaltes Bild",
                descriptionVoucher="Der Computer malt ein täuschend echtes Bild für sie",
                usedVoucher=False,
                untilBlockVoucher=600000000),
        Voucher(idVoucher=2,
                titleVoucher="Software",
                descriptionVoucher="Software für ein Hochschulprojet",
                usedVoucher=False,
                untilBlockVoucher=600000000),
    ]
    # set Institution to Vouchers
    vouchers[0].institution = institutions[0]
    vouchers[1].institution = institutions[0]
    # set Vouchers to Users (and users to vouchers, many-to-many!)
    users[0].vouchers.append(vouchers[0])
    users[1].vouchers.append(vouchers[0])
    users[2].vouchers.append(vouchers[0])
    users[3].vouchers.append(vouchers[0])

    # All objects created, Add and commit to DB:
    objects = [*smartcontracts, *users, *institutions, *projects, *milestones, *vouchers, *transactions,
               *donations]

    for obj in objects:
        session.add(obj)
    session.commit()
