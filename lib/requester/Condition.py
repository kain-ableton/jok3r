#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Condition
###
import ipaddress
from sqlalchemy.sql import and_, or_, not_

from lib.core.Constants import *
from lib.core.Exceptions import FilterException
from lib.db.CommandOutput import CommandOutput
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Option import Option
from lib.db.Product import Product
from lib.db.Result import Result
from lib.db.Service import Service, Protocol
from lib.db.Session import *
from lib.db.Vuln import Vuln
from lib.utils.NetUtils import NetUtils


class Condition:

    def __init__(self, value, filtertype):
        """
        Construct Condition.

        :param str|list value: Condition value, either list or single element
            Example of values:
            Types   Values
            IP      [1.1.1.1,2.2.2.2]     -> means ip = 1.1.1.1 or 2.2.2.2
            Port    [8000-8100,9443]      -> means port = in [8000-8100] or 9443
        :param FilterData(Enum) filtertype: Type of data to filter on
        :raises FilterException: Exception raised in case of invalid value
        """

        self.value = value if type(value) == list else [value]
        # print(self.value)

        self.filtertype = filtertype
        self.mapping = {
            FilterData.IP: self.__translate_ip,
            FilterData.HOST: self.__translate_host,
            FilterData.PORT: self.__translate_port,
            FilterData.PROTOCOL: self.__translate_protocol,
            FilterData.UP: self.__translate_up,
            FilterData.SERVICE: self.__translate_service,
            FilterData.SERVICE_EXACT: self.__translate_service_exact,
            FilterData.SERVICE_ID: self.__translate_service_id,
            FilterData.OS: self.__translate_os,
            FilterData.OS_FAMILY: self.__translate_os_family,
            FilterData.BANNER: self.__translate_banner,
            FilterData.URL: self.__translate_url,
            FilterData.URL_EXACT: self.__translate_url_exact,
            FilterData.HTML_TITLE: self.__translate_html_title,
            FilterData.HTTP_HEADERS: self.__translate_http_headers,
            FilterData.USERNAME: self.__translate_username,
            FilterData.PASSWORD: self.__translate_password,
            FilterData.AUTH_TYPE: self.__translate_auth_type,
            FilterData.USER_AND_PASS: self.__translate_user_and_pass,
            FilterData.ONLY_USER: self.__translate_only_user,
            FilterData.COMMENT_SERVICE: self.__translate_comment_service,
            FilterData.COMMENT_HOST: self.__translate_comment_host,
            FilterData.COMMENT_CRED: self.__translate_comment_cred,
            FilterData.COMMENT_MISSION: self.__translate_comment_mission,
            FilterData.MISSION_EXACT: self.__translate_mission_exact,
            FilterData.MISSION: self.__translate_mission,
            FilterData.CHECK_ID: self.__translate_check_id,
            FilterData.CHECK_NAME: self.__translate_check_name,
            FilterData.COMMAND_OUTPUT: self.__translate_command_output,
            FilterData.VULN: self.__translate_vuln,
            FilterData.OPTION_NAME: self.__translate_option_name,
            FilterData.OPTION_VALUE: self.__translate_option_value,
            FilterData.PRODUCT_TYPE: self.__translate_product_type,
            FilterData.PRODUCT_NAME: self.__translate_product_name,
            FilterData.PRODUCT_VERSION: self.__translate_product_version,
            FilterData.UNSCANNED: self.__translate_unscanned,
        }

    # ------------------------------------------------------------------------------------

    def translate(self):
        """Translate the condition into Sqlalchemy filter"""

        method_translate = self.mapping.get(self.filtertype)
        if not method_translate:
            return None

        result = None
        for v in self.value:
            translated = method_translate(v)
            if translated is not None:
                if result is None:
                    result = (translated)
                else:
                    result = result | (translated)
        # print(result)
        return result

    # ------------------------------------------------------------------------------------

    @staticmethod
    def __translate_ip(value):
        """
        Translate IP address or IP range into Sqlalchemy filter.
        Range must be in CIDR format, e.g. 1.1.1.1/24
        """
        if NetUtils.is_valid_ip(value):
            return (Host.ip == value)
        elif NetUtils.is_valid_ip_range(value):
            return (Host.is_in_ip_range(value))
        else:
            raise FilterException(
                '{value} invalid IP/range'.format(value=value))

    @staticmethod
    def __translate_host(value):
        """
        Translate Hostname into Sqlalchemy filter.
        LIKE %value%
        """
        return (Host.hostname.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_port(value):
        """
        Translate port number or ports range into Sqlalchemy filter.
        Ports range in format: 8000-9000
        """
        if NetUtils.is_valid_port(value):
            return (Service.port == int(value))
        elif NetUtils.is_valid_port_range(value):
            minport, maxport = value.split('-')
            return (Sevrice.port.between(int(minport), int(maxport)))
        else:
            raise FilterException(
                '{value} invalid port/range'.format(value=value))

    @staticmethod
    def __translate_protocol(value):
        """Translate protocol into filter"""
        if value.lower() == 'tcp':
            return (Service.protocol == Protocol.TCP)
        elif value.lower() == 'udp':
            return (Service.protocol == Protocol.UDP)
        else:
            raise FilterException(
                '{value} invalid protocol'.format(value=value))

    @staticmethod
    def __translate_up(value):
        """Translate up status into filter"""
        if type(value) is bool:
            val = value
        elif type(value) is str:
            val = (value.lower() == 'true')
        else:
            raise FilterException(
                '{value} invalid up status'.format(value=value))
        return (Service.up == val)

    @staticmethod
    def __translate_service(value):
        """Translate service name into LIKE filter"""
        return (Service.name.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_service_exact(value):
        """Translate service name into exact filter"""
        return (Service.name == value)

    @staticmethod
    def __translate_service_id(value):
        """Translate service id into filter"""
        return (Service.id == int(value))

    @staticmethod
    def __translate_os(value):
        """Translate host OS into LIKE filter"""
        return (Host.os.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_os_family(value):
        """Translate OS family into LIKE filter"""
        return (Host.os_family.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_banner(value):
        """Translate service banner into LIKE filter"""
        return (Service.banner.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_url(value):
        """Translate URL into LIKE filter"""
        return (Service.url.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_url_exact(value):
        """Translate URL into exact filter"""
        return (Service.url == str(value))

    @staticmethod
    def __translate_html_title(value):
        """Translate HTML title into LIKE filter"""
        return (Service.html_title.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_http_headers(value):
        """Translate HTTP headers into LIKE filter"""
        return (Service.http_headers.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_username(value):
        """Translate username from credentials into LIKE filter"""
        return (Credential.username.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_password(value):
        """Translate password from credentials into LIKE filter"""
        return (Credential.password.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_auth_type(value):
        """Translate credential type into LIKE filter"""
        return (Credential.type.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_user_and_pass(boolean):
        """Create filter for credentials entries with username and password"""
        if boolean:
            return (Credential.username.isnot(None) & Credential.password.isnot(None))
        else:
            return None

    @staticmethod
    def __translate_only_user(boolean):
        """Create filter for credentials entries with only username (no pass known)"""
        if boolean:
            return (Credential.username.isnot(None) & Credential.password.is_(None))
        else:
            return None

    @staticmethod
    def __translate_comment_service(value):
        """Translate service comment into LIKE filter"""
        return (Service.comment.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_comment_host(value):
        """Translate host comment into LIKE filter"""
        return (Host.comment.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_comment_cred(value):
        """Translate credential comment into LIKE filter"""
        return (Credential.comment.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_comment_mission(value):
        """Translate mission comment into LIKE filter"""
        return (Mission.comment.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_mission_exact(value):
        """Translate mission name into exact filter"""
        return (Mission.name == value)

    @staticmethod
    def __translate_mission(value):
        """Translate mission name into LIKE filter"""
        return (Mission.name.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_check_id(value):
        """Translate result id into filter"""
        return (Result.id == int(value))

    @staticmethod
    def __translate_check_name(value):
        """Translate check name from result into LIKE filter"""
        return (Result.check.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_command_output(value):
        """Translate command output text into LIKE filter"""
        return (CommandOutput.output.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_vuln(value):
        """Translate vulnerability name into LIKE filter"""
        return (Vuln.name.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_option_name(value):
        """Translate specific option name into LIKE filter"""
        return (Option.name.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_option_value(value):
        """Translate specific option value into LIKE filter"""
        return (Option.value.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_product_type(value):
        """Translate product type into LIKE filter"""
        return (Product.type.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_product_name(value):
        """Translate product name into LIKE filter"""
        return (Product.name.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_product_version(value):
        """Translate product version into LIKE filter"""
        return (Product.version.ilike('%'+str(value)+'%'))

    @staticmethod
    def __translate_unscanned(value=None):
        """
        Add subquerie as filter to keep only services that have not been 
        scanned yet (i.e. with no checks already run)
        """
        session = Session()
        return not_(
            session.query(Result)
            .filter(Service.id == Result.service_id)
            .exists()
        )
