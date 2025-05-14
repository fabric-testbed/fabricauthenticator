"""FabricAuthenticator for Jupyterhub

Based on CILogon authentication,
in addition checks if user belongs to Fabric JUPYTERHUB COU.

"""
import asyncio
import concurrent
import inspect
import os
from typing import Union, List, Dict

import oauthenticator
import requests
from ldap3.abstract import entry
from tornado import web
from ldap3 import Connection, Server, ALL


JUPYTERHUB_COU = os.getenv('FABRIC_COU_JUPYTERHUB', 'CO:COU:Jupyterhub:members:active')
JUPYTERHUB_ROLE = os.getenv('FABRIC_JUPYTERHUB_ROLE', 'Jupyterhub')


class FabricAuthenticator(oauthenticator.CILogonOAuthenticator):
    """ The FabricAuthenticator inherits from CILogonAuthenticator.
    """
    async def authenticate(self, handler, data=None):
        """ First invoke CILogon authenticate method,
            then check if user has JUPYTERHUB_COU attribute.
        """
        userdict = await super(FabricAuthenticator, self).authenticate(handler, data)
        # check COU
        auth_state = userdict.get("auth_state")
        cilogon_user = auth_state.get("cilogon_user")

        user_email = cilogon_user.get("email")
        user_sub = cilogon_user.get("sub")
        status, roles = self.is_in_allowed_cou_core_api(user_sub)
        if not status:
            self.log.warn("FABRIC user {} is not in {}".format(userdict["name"], JUPYTERHUB_COU))
            raise web.HTTPError(403, "Access not allowed")
        self.log.debug("FABRIC user authenticated")
        auth_state['fabric_roles'] = roles
        return userdict

    async def pre_spawn_start(self, user, spawner):
        """ Populate credentials to spawned notebook environment
        """
        auth_state = await user.get_auth_state()
        self.log.debug("pre_spawn_start: {}".format(user.name))
        if not auth_state:
            return
        spawner.environment['CILOGON_ID_TOKEN'] \
            = auth_state['token_response'].get('id_token', '')
        spawner.environment['CILOGON_REFRESH_TOKEN'] \
            = auth_state['token_response'].get('refresh_token', '')
        self.log.info(f"FABRIC {user} token: {auth_state['token_response'].get('refresh_token', '')}")
        # setup environment
        nb_user = str(user.name)
        if "@" in nb_user:
            nb_user = nb_user.split("@", 1)[0]
        spawner.environment['NB_USER'] = nb_user
        self.log.debug(f"Environment: {spawner.environment}")

    async def refresh_user(self, user, handler=None):
        """
        1. Check if token is valid and then call _shutdown_servers and then redirect to login page
        2. If time of refresh_user is set as token expiry, directly call _shutdown_servers and then redirect to login page
        This is shutdown single user servers and once redirected to login, auth flow gets run and new tokens are passed to spawner
        """
        await self._shutdown_servers(user, handler)
        handler.clear_cookie("jupyterhub-hub-login")
        handler.clear_cookie("jupyterhub-session-id")
        handler.redirect('/hub/logout')
        return True

    @staticmethod
    async def maybe_future(obj):
        """Return an asyncio Future
        Use instead of gen.maybe_future
        For our compatibility, this must accept:
        - asyncio coroutine (gen.maybe_future doesn't work in tornado < 5)
        - tornado coroutine (asyncio.ensure_future doesn't work)
        - scalar (asyncio.ensure_future doesn't work)
        - concurrent.futures.Future (asyncio.ensure_future doesn't work)
        - tornado Future (works both ways)
        - asyncio Future (works both ways)
        """
        if inspect.isawaitable(obj):
            # already awaitable, use ensure_future
            return asyncio.ensure_future(obj)
        elif isinstance(obj, concurrent.futures.Future):
            return asyncio.wrap_future(obj)
        else:
            # could also check for tornado.concurrent.Future
            # but with tornado >= 5.1 tornado.Future is asyncio.Future
            f = asyncio.Future()
            f.set_result(obj)
            return f

    async def _shutdown_servers(self, user, handler):
        """Shutdown servers for logout
        Get all active servers for the provided user, stop them.
        """
        active_servers = [
            name
            for (name, spawner) in user.spawners.items()
            if spawner.active and not spawner.pending
        ]
        if active_servers:
            self.log.info("Shutting down %s's servers", user.name)
            futures = []
            for server_name in active_servers:
                result = handler.stop_single_user(user, server_name)
                futures.append(self.maybe_future(obj=result))
            await asyncio.gather(*futures)

    def is_in_allowed_cou_core_api(self, sub: str) -> tuple[bool, list]:
        """
        Checks if a user is in the Comanage JUPYTERHUB COU based on roles from the FABRIC Core API.

        Args:
            sub (str): The OIDC subject identifier.

        Returns:
            bool: True if the user has the JUPYTERHUB_ROLE, False otherwise.
        """
        core_api_host = os.getenv('FABRIC_CORE_API_HOST', '')
        core_api_token = os.getenv('FABRIC_CORE_API_BEARER_TOKEN', '')

        try:
            user_info = self.get_fabric_user_info(sub=sub, token=core_api_token, api_server_url=core_api_host)
        except Exception as e:
            self.log.error(f"Failed to fetch user info from core API: {e}")
            return False, []

        results = user_info.get("results", [])
        if not results:
            self.log.warning(f"No results found in Core API for sub: {sub}")
            return False, []

        roles = results[0].get("roles", [])
        for role in roles:
            if role.get("name") == JUPYTERHUB_ROLE:
                self.log.debug(f"User has required role: {JUPYTERHUB_ROLE}")
                return True, roles

        self.log.debug(f"User does not have required role: {JUPYTERHUB_ROLE}")
        return False, []

    def is_in_allowed_cou(self, email, sub):
        """ Checks if user is in Comanage JUPYTERHUB COU.

            Args:
                email: i.e. email
                sub: user sub

            Returns:
                Boolean value: True if username has attribute of JUPYTERHUB_COU, False otherwise
        """
        attributelist = self.get_ldap_attributes(email, sub)
        if attributelist:
            self.log.debug("attributelist acquired.")
            # Check if OIDC sub is registered with FABRIC;
            # protect against Idps which use same email addresses
            if sub is not None and attributelist['uid']:
                if sub not in attributelist['uid']:
                    return False
            if attributelist['isMemberOf']:
                for attribute in attributelist['isMemberOf']:
                    if attribute == JUPYTERHUB_COU:
                        return True
        return False

    @staticmethod
    def get_fabric_user_info(sub: str, token: str, api_server_url: str) -> dict:
        """
        Query the FABRIC CORE API for user authorization details using OIDC 'sub' and a bearer token.

        Args:
            sub (str): The OIDC sub URL (e.g., 'http://cilogon.org/serverF/users/1464').
            token (str): The services authorization token.
            api_server_url (str): The base URL of the FABRIC CORE API.

        Returns:
            dict: JSON response containing user info, roles, and status.
        """
        url = f"{api_server_url}/people/services-auth"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        params = {"sub": sub}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # raises HTTPError if the status is 4xx or 5xx

        return response.json()

    @staticmethod
    def get_ldap_attributes(email: str, sub: str) -> Union[entry.Entry, None]:
        """Get the LDAP attributes from the Fabric CILogon instance.

        Args:
            email (str): The email address of the user.
            sub (str): The subject identifier (sub) of the user.

        Returns:
            Union[entry.Entry, None]: The attributes list if found, otherwise None.
        """
        # Fetch environment variables with defaults
        ldap_host = os.getenv('LDAP_HOST', '')
        ldap_user = os.getenv('LDAP_USER', '')
        ldap_password = os.getenv('LDAP_PASSWORD', '')
        ldap_search_base = os.getenv('LDAP_SEARCH_BASE', '')

        # Create the server and connection
        server = Server(ldap_host, use_ssl=True, get_info=ALL)
        conn = Connection(server, ldap_user, ldap_password, auto_bind=True)

        # Construct the search filter
        ldap_search_filter = f'(uid={sub})' if sub else f'(mail={email})'

        # Perform the search
        profile_found = conn.search(
            search_base=ldap_search_base,
            search_filter=ldap_search_filter,
            attributes=['isMemberOf', 'uid', 'mail']
        )

        # Retrieve the attributes if found
        attributes = conn.entries[0] if profile_found else None

        # Unbind the connection
        conn.unbind()
        return attributes

    def check_username_claim(self, claimlist, resp_json):
        return self.check_username_claim_core_api(resp_json=resp_json)

    def check_username_claim_core_api(self, resp_json: Dict[str, Union[str, List[str]]]) -> str:
        """
        Determine the JupyterHub username based on OIDC claims or Core API lookup using the user's `sub`.

        Priority:
        1. Use `uuid` from FABRIC Core API if `sub` is available and matches a record.
        2. Fallback to email if available in OIDC claims.

        Args:
            resp_json (Dict[str, Union[str, List[str]]]): Userinfo from CILogon.

        Returns:
            str: The resolved JupyterHub username (UUID or email).

        Raises:
            web.HTTPError: If no username can be determined.
        """
        core_api_host = os.getenv('FABRIC_CORE_API_HOST', '')
        core_api_token = os.getenv('FABRIC_CORE_API_BEARER_TOKEN', '')

        email = resp_json.get("email")
        sub = resp_json.get("sub")

        username = email  # fallback default

        if isinstance(sub, list):
            sub = sub[0]

        if sub:
            try:
                user_info = self.get_fabric_user_info(sub=sub, token=core_api_token,
                                                      api_server_url=core_api_host)
                results = user_info.get("results", [])
                if results:
                    uuid = results[0].get("uuid")
                    if uuid:
                        username = uuid
                        self.log.info(f"Using FABRIC UUID as username: {uuid}")
            except Exception as e:
                self.log.error(f"Error fetching user info for sub={sub}: {e}")

        if not username:
            self.log.error(f"Sub: {sub} → No valid username could be derived from claims or Core API")
            raise web.HTTPError(500, "Failed to get username from CILogon")

        return username

    def check_username_claim_ldap(self, claimlist: List[str], resp_json: Dict[str, Union[str, List[str]]]) -> str:
        """
        Determine the username based on the available claims and LDAP attributes.

        CILogonOAuthenticator expects either ePPN or email to determine the JupyterHub container username.
        To handle cases where only 'sub' information is available, fetch the email from LDAP and set it as the username.

        Address issues reported in:
        - https://fabric-testbed.atlassian.net/browse/FIP-714
        - https://fabric-testbed.atlassian.net/browse/FIP-715
        - https://fabric-testbed.atlassian.net/browse/FIP-724

        Args:
            claimlist (List[str]): List of claims to check for the username.
            resp_json (Dict[str, Union[str, List[str]]]): Response JSON containing user information.

        Returns:
            str: The determined username.

        Raises:
            web.HTTPError: If no valid username can be determined.
        """
        # HACK for handling email aliases; always determine the email from LDAP by querying on sub
        username = None
        #for claim in claimlist:
        #    username = resp_json.get(claim)
        #    if username:
        #        return username

        # Hack when user claims only has sub
        email = resp_json.get("email")
        sub = resp_json.get("sub")
        if sub is not None:
            if isinstance(sub, list):
                sub = sub[0]
            attributelist = self.get_ldap_attributes(None, sub)
            if attributelist is not None:
                self.log.info(f"Attributelist acquired for determining username: {attributelist}")

                # If there is only one email in the attributes list, use it as the username
                if len(attributelist['mail']) == 1:
                    username = str(attributelist['mail'])
                else:
                    # If the email from the response is not in the LDAP attributes, use the first available email
                    if email is None or email not in attributelist['mail']:
                        username = str(attributelist['mail'][0])
                    else:
                        username = email

        if not username:
            error_message = (
                f"Sub: {sub} No username claim: '{self.username_claim}' found in response: {resp_json} claimlist: {claimlist}"
                if len(claimlist) >= 2 else
                f"Sub: {sub} Username claim: '{self.username_claim}' not found in response: {resp_json} claimlist: {claimlist}"
            )
            self.log.error(error_message)
            raise web.HTTPError(500, "Failed to get username from CILogon")

        return username