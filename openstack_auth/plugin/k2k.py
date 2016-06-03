# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from keystoneauth1 import exceptions as keystone_exceptions
from keystoneauth1.identity.v3.k2k import Keystone2Keystone

from openstack_auth import exceptions
from openstack_auth.plugin import base
from openstack_auth import utils

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

LOG = logging.getLogger(__name__)

__all__ = ['K2KAuthPlugin']


class K2KAuthPlugin(base.BasePlugin):
    """Authenticate using keystone to keystone federation.

    This plugin uses other v3 plugins to authenticate a user to a
    identity provider in order to authenticate the user to a service
    provider
    """

    def get_plugin(self, service_provider=None, auth_url=None,
                   plugins=[], **kwargs):
        if utils.get_keystone_version() < 3 or not service_provider:
            return None

        idp_choice = getattr(settings, 'K2K_INITIAL_CHOICE', 'KeystoneIDP')

        # User selected the idp choice, so use the other plugins
        if service_provider == idp_choice:
            return None

        for plugin in plugins:
            unscoped_idp_auth = plugin.get_plugin(plugins=plugins,
                                                  auth_url=auth_url, **kwargs)
            if unscoped_idp_auth:
                break
        else:
            LOG.debug('Could not find base authentication backend for '
                      'K2K plugin with the provided credentials.')
            return None

        scoped_idp_auth = self._scope_the_unscoped_idp_auth(unscoped_idp_auth,
                                                            auth_url)

        session = utils.get_session()
        if scoped_idp_auth.get_sp_auth_url(session, service_provider) is None:
            raise exceptions.KeystoneAuthException(
                _('Could not find service provider id on keystone.'))

        unscoped_auth = Keystone2Keystone(
            base_plugin=scoped_idp_auth,
            service_provider=service_provider)
        return unscoped_auth

    def _scope_the_unscoped_idp_auth(self, unscoped_idp_auth, auth_url):
        """Scope the unscoped token

        The K2k Auth Plugin needs a scoped auth in order to
        work. This function gets the first project that the user
        can log scope to and returns the scope auth.
        """
        unscoped_auth_ref = utils.get_access_info(unscoped_idp_auth)
        session = utils.get_session()
        projects = self.list_projects(
            session, unscoped_idp_auth, unscoped_auth_ref)

        scoped_auth = None
        for project in projects:
            token = unscoped_auth_ref.auth_token
            scoped_auth = utils.get_token_auth_plugin(auth_url,
                                                      token=token,
                                                      project_id=project.id)

            try:
                scoped_auth_ref = scoped_auth.get_access(session)  # noqa
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure):
                pass
            else:
                break
        return scoped_auth
