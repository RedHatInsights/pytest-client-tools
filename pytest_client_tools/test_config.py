# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import os
from contextlib import contextmanager

import toml
from dynaconf import Dynaconf, Validator

try:
    # dynaconf>=3.2 applies this to the values of the env vars before
    # parsing them
    from dynaconf.utils.parse_conf import boolean_fix, parse_conf_data
except ImportError:

    def boolean_fix(value):
        return value

    def parse_conf_data(value, tomlfy=True, box_settings=None):
        # parse the value the same way dynaconf does, as the right-hand
        # side of a TOML assignment, keeping bare (invalid TOML) values as
        # strings
        try:
            return toml.loads("value = {}".format(value))["value"]
        except (toml.TomlDecodeError, ValueError):
            return value


# Settings keys whose validators assert a list value: their values must
# override (replace) the values from the lower layers (the [default]
# environment, the settings files), not merge (concatenate) with them.
LIST_SETTINGS_KEYS = ("candlepin.activation_keys", "candlepin.environments")

SETTINGS_FILES = ("settings.toml", ".secrets.toml")

# prefix of the environment variables that provide the settings
ENVVAR_PREFIX = "PYTEST_CLIENT_TOOLS"

# env var prefix of the raw views of the settings files: distinct from
# ENVVAR_PREFIX so that no environment variable can inject values into the
# "<environment>.<key>" paths they are read through
RAW_FILES_ENVVAR_PREFIX = ENVVAR_PREFIX + "_RAW_FILE"


@contextmanager
def _without_empty_config_env_vars():
    """
    Temporarily remove from the environment the empty (or whitespace-only)
    PYTEST_CLIENT_TOOLS_* variables, so that Dynaconf does not load them as
    empty settings: an empty variable must behave as unset, and not
    override with an empty value the one coming from the settings files.

    The environment is restored on exit, exactly as it was found.
    """
    removed = {}
    try:
        for name in list(os.environ):
            if name.startswith(ENVVAR_PREFIX + "_") and not os.environ[name].strip():
                removed[name] = os.environ.pop(name)
        yield
    finally:
        os.environ.update(removed)


class TestConfig:
    """
    Configuration for the tests.

    Every settings key can be provided through environment variables, so no
    settings file is needed:

    - the name of an environment variable is the ``PYTEST_CLIENT_TOOLS``
      prefix, followed by the path of the key with each ``.`` replaced by
      ``__`` (Dynaconf nested separator), all uppercase; for example
      ``candlepin.username`` maps to
      ``PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME``
    - a flat (top level) key maps to ``PYTEST_CLIENT_TOOLS_<KEY>``
    - the value is parsed as a TOML value: unquoted values are used as
      strings unless they look like numbers, booleans or lists; use TOML
      quoting (for example ``'"12345"'``) to force a string that looks like
      a number
    - environment variables override the values from ``settings.toml`` and
      ``.secrets.toml`` for the currently selected Dynaconf environment
      (``ENV_FOR_DYNACONF``, e.g. ``stage`` or ``prod``); other keys of the
      same section keep the values from the files
    - the list-valued settings (``candlepin.activation_keys``,
      ``candlepin.environments``) replace, as a whole, the values of the
      lower layers instead of being concatenated with them
    - the settings files are optional: if they do not exist, the
      configuration is fully satisfiable from environment variables only
    """

    def __init__(self):
        # Dynaconf reads the environment not only when it is constructed,
        # but also (once, in bulk) at the first access of the settings:
        # keep the empty PYTEST_CLIENT_TOOLS_* variables out of the way
        # for the whole initialization
        with _without_empty_config_env_vars():
            self._settings = Dynaconf(
                default_env="default",
                environments=True,
                envvar_prefix=ENVVAR_PREFIX,
                settings_files=list(SETTINGS_FILES),
                # merge the files and the environment variables on top of
                # them instead of replacing whole sections, so that the
                # configuration is satisfiable from environment variables
                # only; the list-valued settings are exempted afterwards
                # (see _normalize_list_settings)
                merge_enabled=True,
            )
            # a separate raw view of each settings file, without merging
            # and without the environments feature, so that
            # "<environment>.<key>" returns the original value from that
            # file; used to compute the value of the list-valued settings
            self._raw_files = [
                Dynaconf(
                    envvar_prefix=RAW_FILES_ENVVAR_PREFIX,
                    settings_files=[filename],
                    merge_enabled=False,
                )
                for filename in SETTINGS_FILES
            ]
            self._settings.validators.register(
                Validator("candlepin.host"),
                Validator("candlepin.port", is_type_of=int, gt=0, lt=65536),
                Validator("candlepin.prefix", startswith="/"),
                Validator("candlepin.insecure", is_type_of=bool, default=False),
                Validator("candlepin.username"),
                Validator(
                    "candlepin.password",
                    must_exist=True,
                    when=Validator("candlepin.username", must_exist=True),
                ),
                Validator("candlepin.activation_keys", is_type_of=list),
                Validator(
                    "candlepin.org",
                    is_type_of=str,
                    # Fix for a regression in dynaconf, can be removed with
                    # dynaconf>=3.3.0
                    # https://github.com/dynaconf/dynaconf/issues/1064
                    #  "Validator default string parsed to number"
                    cast=str,
                    must_exist=True,
                    when=Validator(
                        "candlepin.activation_keys",
                        is_type_of=list,
                        must_exist=True,
                    ),
                ),
                Validator("candlepin.environments", is_type_of=list),
                Validator("insights.legacy_upload", is_type_of=bool),
                Validator("insights.auto_update", is_type_of=bool),
                Validator(
                    "insights.base_url",
                    default="https://cert-api.access.redhat.com/r/insights/platform",
                ),
                Validator(
                    "insights.ca_path",
                    default="/etc/insights-client/cert-api.access.redhat.com.pem",
                ),
                Validator("insights.insecure", is_type_of=bool, default=False),
            )
            self._settings.validators.validate()
            # dynaconf<3.2 does not write the value cast by a validator
            # back into the settings, so normalize it explicitly; the
            # uppercase key matches how dynaconf names the settings on
            # every version
            org = self._settings.get("candlepin.org")
            if org is not None:
                self._settings.set("CANDLEPIN.ORG", str(org))
            self._normalize_list_settings()

    def _normalize_list_settings(self):
        """
        Give the list-valued settings replace semantics instead of the
        merge (concatenation) that merge_enabled applies to them.

        These settings are consumed as a whole (for example, rhc registers
        with candlepin.activation_keys[0]): concatenating the values of
        different layers would silently mix their credentials, for example
        registering with the activation key of [default] against the
        Candlepin of the selected environment. Give them instead the value
        of the highest layer that defines the key: the environment variable
        if set, otherwise the selected environment of the settings files
        (with .secrets.toml winning over settings.toml), otherwise
        [default].
        """
        # replacement values grouped by section, to replace each section
        # only once
        replacements = {}
        for key in LIST_SETTINGS_KEYS:
            value = self._effective_list_value(key)
            if value is None or self._settings.get(key) == value:
                # nothing defines the key anywhere, or dynaconf already
                # resolved it to the expected value: nothing to do
                continue
            section, _, name = key.rpartition(".")
            replacements.setdefault(section, {})[name] = value
        for section, values in replacements.items():
            # replace the whole section, as merge=False is unsupported by
            # the dotted form of set(); the other keys are carried over
            # from the current (merged) value, re-read through their
            # dotted paths: dynaconf<3.2 keeps the values of the files and
            # the ones of the env vars under case-variant spellings of the
            # same key (e.g. "host" and "HOST") in the section, and only
            # the dotted reads resolve to the effective values
            merged = {}
            names = {name.casefold() for name in (self._settings.get(section) or {})}
            for name in names:
                merged[name.upper()] = self._settings.get(".".join((section, name)))
            merged.update({name.upper(): value for name, value in values.items()})
            # drop the section before writing it back: with the global
            # merge enabled, dynaconf<3.2 merges the existing value into
            # the new one even with merge=False, which would keep the
            # stale case-variant spellings (and their values) in place
            self._settings.unset(section, force=True)
            self._settings.set(section.upper(), merged, merge=False)

    def _effective_list_value(self, key):
        """
        The value a list-valued settings key should have, as a whole: the
        one of the highest layer that defines the key, that is the
        environment variable if set (an empty one counts as unset),
        otherwise the selected environment in the settings files (with
        .secrets.toml winning over settings.toml), otherwise [default].
        """
        env_var = ENVVAR_PREFIX + "_" + key.upper().replace(".", "__")
        raw_value = os.environ.get(env_var)
        if raw_value is not None and raw_value.strip():
            return parse_conf_data(
                boolean_fix(raw_value),
                tomlfy=True,
                box_settings=self._settings,
            )
        # without ENV_FOR_DYNACONF the settings behave as if the default
        # environment was selected
        environments = (os.environ.get("ENV_FOR_DYNACONF", "default"), "default")
        for environment in environments:
            # the raw files are in increasing precedence order, so they are
            # read the other way around
            for raw_file in reversed(self._raw_files):
                value = raw_file.get("{}.{}".format(environment, key))
                if value is not None:
                    return value
        return None

    def _non_empty_setting(self, *path):
        """
        Query for a configuration key, treating an empty or whitespace-only
        value (for example an empty env var, or an empty string in a
        settings file) as no value at all: without this, the tests would
        for example try to connect to an empty hostname instead of being
        skipped.

        :param path: The path/name of the configuration key
        :type path: str
        """
        value = self._settings.get(".".join(path))
        if value is not None and not str(value).strip():
            return None
        return value

    @property
    def is_external(self):
        """
        Determines whether an external Candlepin is configured.
        """
        try:
            host = self._non_empty_setting("candlepin", "host")
            username = self._non_empty_setting("candlepin", "username")
            password = self._non_empty_setting("candlepin", "password")
            return (
                host is not None
                and self._settings.get("candlepin.port") is not None
                and self._settings.get("candlepin.prefix") is not None
                and (
                    (username is not None and password is not None)
                    or (
                        self._settings.get("candlepin.activation_keys") is not None
                        and self._settings.get("candlepin.org") is not None
                    )
                )
            )
        except KeyError:
            return False

    @property
    def environment(self):
        """
        Returns the Dynaconf environment currently in use.
        """
        return self._settings.current_env

    def get(self, *path):
        """
        Query for a configuration key.

        :param path: The path/name of the configuration key
        :type path: str
        """
        return self._settings[".".join(path)]
