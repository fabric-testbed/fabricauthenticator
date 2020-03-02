"""FabricAuthenticator for Jupyterhub

Based on CILogon authentication,
in addition checks if user belongs to Fabric JUPYTERHUB COU.

"""
import os
import oauthenticator
from tornado import web
from ldap3 import Connection, Server, ALL

JUPYTERHUB_COU = os.getenv('FABRIC_COU_JUPYTERHUB', 'CO:COU:Jupyterhub:members:active')


class FabricAuthenticator(oauthenticator.CILogonOAuthenticator):
    """ The FabricAuthenticator inherits from CILogonAuthenticator.
    """
    async def authenticate(self, handler, data=None):
        """ First invoke CILogon authenticate method,
            then check if user has JUPYTERHUB_COU attribute.
        """
        userdict = await super(FabricAuthenticator, self).authenticate(handler, data)

        # check COU
        if not self.is_in_allowed_cou(userdict["name"]):
            self.log.warn("FABRIC user {} is not in {}".format(userdict["name"], JUPYTERHUB_COU))
            raise web.HTTPError(403, "Access not allowed")

        self.log.debug("FABRIC user authenticated")
        return userdict

    def is_in_allowed_cou(self, username):
        """ Checks if user is in Comanage JUPYTERHUB COU.

            Args:
                username: i.e. ePPN

            Returns:
                Boolean value: True if username has attribute of JUPYTERHUB_COU, False otherwise
        """
        attributelist = self.get_ldap_attributes(username)
        if attributelist:
            self.log.debug("attributelist acquired.")
            if attributelist['isMemberOf']:
                for attribute in attributelist['isMemberOf']:
                    if attribute == JUPYTERHUB_COU:
                        return True
        return False

    @staticmethod
    def get_ldap_attributes(username):
        """ Get the ldap attributes from Fabric CILogon instance.

            Args:
                username: i.e. ePPN

            Returns:
                The attributes list
        """
        server = Server(os.getenv('LDAP_HOST', ''), use_ssl=True, get_info=ALL)
        ldap_user = os.getenv('LDAP_USER', '')
        ldap_password = os.getenv('LDAP_PASSWORD', '')
        ldap_search_base = os.getenv('LDAP_SEARCH_BASE', '')
        ldap_search_filter = '(eduPersonPrincipalName=' + username + ')'
        conn = Connection(server, ldap_user, ldap_password, auto_bind=True)
        profile_found = conn.search(ldap_search_base,
                                    ldap_search_filter,
                                    attributes=[
                                        'isMemberOf',
                                    ])
        if profile_found:
            attributes = conn.entries[0]
        else:
            attributes = []
        conn.unbind()
        return attributes

