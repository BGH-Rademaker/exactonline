# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
Provides an INI storage class to the Exact Online REST API Library.

This file is part of the Exact Online REST API Library in Python
(EORALP), licensed under the LGPLv3+.
Copyright (C) 2015-2018 Walter Doekes, OSSO B.V.

Usage:

    storage = IniStorage('read_and_writable.ini')

Example ini file:

    [server]
    auth_url = https://start.exactonline.co.uk/api/oauth2/auth
    rest_url = https://start.exactonline.co.uk/api
    token_url = https://start.exactonline.co.uk/api/oauth2/token

    [application]
    base_url = https://example.com
    client_id = {12345678-abcd-1234-abcd-0123456789ab}
    client_secret = ZZZ999xxx000

    [transient]
    access_expiry = 1426492503
    access_token = dAfjGhB1k2tE2dkG12sd1Ff1A1fj2fH2Y1j1fKJl2f1sD1ON275zJNUy...
    code = dAfj!hB1k2tE2dkG12sd1Ff1A1fj2fH2Y1j1fKJl2f1sD1ON275zJNUy...
    division = 123456
    refresh_token = SDFu!12SAah-un-56su-1fj2fH2Y1j1fKJl2f1sDfKJl2f1sD11FfUn1...

"""
from .base import ExactOnlineConfig, MissingSetting
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
from azure.appconfiguration import AzureAppConfigurationClient, ConfigurationSetting

try:
    from configparser import NoSectionError, NoOptionError, ConfigParser
except ImportError:  # python2
    from ConfigParser import (
        NoSectionError, NoOptionError,
        SafeConfigParser as ConfigParserOldStyle)

    class ConfigParser(ConfigParserOldStyle, object):
        """
        We require this adapter to upgrade the RawConfigParser to a
        new-style class. Only needed in Python2.
        """
        def __init__(self, **kwargs):
            # Must call this __init__ manually :(
            ConfigParserOldStyle.__init__(self, **kwargs)
            super(ConfigParser, self).__init__(**kwargs)

class AzureConfig():
    def __init__(self, credential=None, vault_url=None, app_config_url=None):
        if not vault_url:
            raise ValueError("vault_url is required for AzureConfig.")
        if not app_config_url:
            raise ValueError("app_config_url is required for AzureConfig.")

        self.credential = credential or DefaultAzureCredential()
        self.vault_url = vault_url
        self.app_config_url = app_config_url

class IniStorage(ExactOnlineConfig, ConfigParser):
    """
    Configuration based on the SafeConfigParser and the
    ExactOnlineConfig.

    Takes a ``filename_or_fp`` which can either be a filename or a file
    pointer. If it is a filename, all set() operations are destructive:
    the file will be automatically updated.
    """
    def __init__(self, filename_or_fp,  azure_config: AzureConfig = None, **kwargs):
        super(IniStorage, self).__init__(**kwargs)

        if hasattr(filename_or_fp, 'read'):
            if hasattr(self, 'read_file'):
                self.read_file(filename_or_fp)
            else:
                self.readfp(filename_or_fp)  # python<3.2
            self.overwrite = False
        else:
            self.read([filename_or_fp])
            self.overwrite = filename_or_fp

        try:
            if azure_config:
                self.credential = azure_config.credential
                self.vault_url = azure_config.vault_url
                self.app_config_url = azure_config.app_config_url

                self.secret_client = SecretClient(
                    vault_url=self.vault_url,
                    credential=self.credential
                    )
                self.app_config_client = AzureAppConfigurationClient(
                    base_url=self.app_config_url,
                    credential=self.credential
                )
                self.azure = True

        except ImportError:
            print("Azure Key Vault integration is not available. "
                    "Please install the azure-identity and azure-keyvault-secrets "
                    "packages to enable this feature.")
            self.azure = False
            
        except Exception as e:
            print(f"Error initializing Azure Key Vault client: {e}")
            self.azure = False
            
            

    def get(self, section, option, az_resource=None, **kwargs):
        """
        Get method that raises MissingSetting if the value was unset.

        This differs from the SafeConfigParser which may raise either a
        NoOptionError or a NoSectionError.

        We take extra **kwargs because the Python 3.5 configparser extends the
        get method signature and it calls self with those parameters.

            def get(self, section, option, *, raw=False, vars=None,
                    fallback=_UNSET):
        """

        ret = None

        if self.azure:
            secret, value = None, None
            if az_resource == 'kv':
                ret = self.get_keyvault_secret(option)
                print(f"Fetching secret {option} from Azure Key Vault: {ret}.")
            elif az_resource == 'ac':
                ret = self.get_app_config_value(option)
                print(f"Fetching value {option} from Azure App Configuration: {ret}.")

        if ret is None:
            try:
                ret = super(ExactOnlineConfig, self).get(section, option, **kwargs)
                print(f"Fetching {option} from local INI file: {ret} and az_resource={az_resource}")
            except (NoOptionError, NoSectionError):
                raise MissingSetting(option, section)

        return ret

    def set(self, section, option, value, az_resource=None):
        """
        Set method that (1) auto-saves if possible and (2) auto-creates
        sections.
        """
        try:
            super(ExactOnlineConfig, self).set(section, option, value)
        except NoSectionError:
            self.add_section(section)
            super(ExactOnlineConfig, self).set(section, option, value)

        if self.azure:
            if az_resource == 'kv':
                self.set_keyvault_secret(option, value)
                print(f"Adding secret {option} to Azure Key Vault: {value}.")
            elif az_resource == 'ac':
                print(f"Adding value {option} to Azure App Configuration: {value}.")
                self.set_app_config_value(option, value)

        # Save automatically!
        self.save()

    def save(self):
        if self.overwrite:
            with open(self.overwrite, 'w') as output:
                self.write(output)

    def set_keyvault_secret(self, key, value):
        try:
            key = 'EXACT-ONLINE-%s' % (key)
            key = key.replace(' ', '-').replace('_', '-').replace('/', '-').upper()
            self.secret_client.set_secret(key, value)
        except ResourceNotFoundError:
            pass
        except Exception as e:
            pass

    def get_keyvault_secret(self, key):
        try:
            key = 'EXACT-ONLINE-%s' % (key)
            key = key.replace(' ', '-').replace('_', '-').replace('/', '-').upper()
            secret = self.secret_client.get_secret(key)
            return secret.value
        except Exception as e:
            return None

    def set_app_config_value(self, key, value):
        try:
            key = 'exact_online/%s' % (key)
            key = key.replace(' ', '_').replace('-', '_').lower()
            configuration_setting = ConfigurationSetting(
                key=key,
                value=value
            )

            self.app_config_client.set_configuration_setting(
                configuration_setting=configuration_setting
            )
        except ResourceNotFoundError:
            pass
        except Exception as e:
            pass

    def get_app_config_value(self, key):
        try:
            key = 'exact_online/%s' % (key)
            key = key.replace(' ', '_').replace('-', '_').lower()
            value = self.app_config_client.get_configuration_setting(
                key=key
            )
            return value.value
        except Exception as e:
            return None