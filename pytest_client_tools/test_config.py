# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import os
import warnings
from contextlib import contextmanager

import toml
from dynaconf import Dynaconf, Validator

from . import vault

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

# the dotted paths of the list-valued settings, as tuples: the generic
# sentinel walker skips them, as they are resolved from their effective
# value instead (see TestConfig._resolve_list_settings)
_LIST_SETTINGS_PATHS = {tuple(key.split(".")) for key in LIST_SETTINGS_KEYS}

SETTINGS_FILES = ("settings.toml", ".secrets.toml")

# prefix of the environment variables that provide the settings
ENVVAR_PREFIX = "PYTEST_CLIENT_TOOLS"

# env var prefix of the raw views of the settings files: distinct from
# ENVVAR_PREFIX so that no environment variable can inject values into the
# "<environment>.<key>" paths they are read through
RAW_FILES_ENVVAR_PREFIX = ENVVAR_PREFIX + "_RAW_FILE"

# marker for a settings value whose sentinels could not be resolved:
# the key is written back as absent, exactly as if it was never
# defined (an empty list would not be absent for the consumers, e.g.
# candlepin.activation_keys[0], and an empty string is not absent
# either, e.g. for candlepin.org or insights.base_url)
_ABSENT = object()


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


def _uppercase_keys(value):
    """
    A copy of a settings value with the keys of all its nested
    dictionaries uppercased: dynaconf names the settings that way on
    every version.
    """
    if isinstance(value, dict):
        return {key.upper(): _uppercase_keys(item) for key, item in value.items()}
    return value


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
    - a settings value can be a ``@vault:<path>:<key>`` sentinel: it is
      resolved, when the configuration is loaded, into the value stored
      in the Vault kv2 secret store at ``<path>``, under ``<key>``
      (see :mod:`pytest_client_tools.vault`)
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
                # (see _resolve_list_settings)
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
            # resolve the @vault sentinels of the loaded settings
            # before registering the validators, so that they validate
            # (and the fixtures consume) the real values, or their
            # absence; the list-valued settings are resolved from
            # their effective value first, so that a sentinel replaced
            # by a higher layer is never resolved, and the same
            # resolver is reused for both passes
            self._vault_failures = {}
            self._vault_resolver = vault.VaultResolver()
            self._resolve_list_settings()
            self._resolve_vault_sentinels()
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

    def _resolve_list_settings(self):
        """
        Give the list-valued settings the value of their highest layer,
        resolving their sentinels from that effective value.

        These settings are consumed as a whole (for example, rhc
        registers with candlepin.activation_keys[0]): concatenating
        the values of different layers would silently mix their
        credentials, for example registering with the activation key
        of [default] against the Candlepin of the selected
        environment. They get instead the value of the highest layer
        that defines the key: the environment variable if set,
        otherwise the selected environment of the settings files (with
        .secrets.toml winning over settings.toml), otherwise
        [default].

        Their sentinels are resolved here, from the effective value,
        before the generic resolution: a sentinel in a list that a
        higher layer replaces is not part of the effective
        configuration, and resolving it would warn about — or, in
        strict mode, fail the run for — a value that is never used. A
        list whose sentinels cannot be resolved makes the key absent
        as a whole, exactly as if no layer defined it.
        """
        # replacement values grouped by section, to replace each
        # section only once; None removes the key
        replacements = {}
        for key in LIST_SETTINGS_KEYS:
            # this first access of the settings is also the one that
            # loads the PYTEST_CLIENT_TOOLS_* environment variables in
            # bulk
            value = self._effective_list_value(key)
            current = self._settings.get(key)
            if value is None and current is None:
                # nothing defines the key anywhere: nothing to do
                continue
            if value is not None and current == value:
                # dynaconf already resolved the key to the expected
                # value: nothing to do
                continue
            # value is None here only when the effective list holds
            # sentinels that could not be resolved (current is then
            # not None): the key is removed as a whole
            section, _, name = key.rpartition(".")
            replacements.setdefault(section, {})[name] = value
        for section, values in replacements.items():
            # replace the whole section, as merge=False is unsupported
            # by the dotted form of set(); the other keys are carried
            # over from the current (merged) value, re-read through
            # their dotted paths: dynaconf<3.2 keeps the values of the
            # files and the ones of the env vars under case-variant
            # spellings of the same key (e.g. "host" and "HOST") in
            # the section, and only the dotted reads resolve to the
            # effective values
            merged = {}
            names = {name.casefold() for name in (self._settings.get(section) or {})}
            for name in names:
                merged[name.upper()] = self._settings.get(".".join((section, name)))
            for name, value in values.items():
                if value is None:
                    merged.pop(name.upper(), None)
                else:
                    merged[name.upper()] = value
            # drop the section before writing it back: with the global
            # merge enabled, dynaconf<3.2 merges the existing value
            # into the new one even with merge=False, which would keep
            # the stale case-variant spellings (and their values) in
            # place
            self._settings.unset(section, force=True)
            self._settings.set(section.upper(), merged, merge=False)

    def _resolve_vault_sentinels(self):
        """
        Resolve the ``@vault:`` sentinels of the loaded settings.

        Each string value (and each element of a list value) starting
        with ``@vault:`` is replaced with the value read from the Vault
        server. A value holding any unresolved sentinel is absent as a
        whole: a partially-resolved value must never be used, and an
        absent key behaves exactly as one that was never defined (the
        validators' defaults apply, ``must_exist`` fires as for a
        missing key, and the consumers see the same absence they see
        for a value missing from the configuration), so the tests
        depending on the affected values skip or fail exactly as they
        do today when the values are missing.

        Without Vault credentials, or when Vault is configured but a
        value cannot be read, the unresolved sentinels are summarized
        by a warning, raised through :func:`warnings.warn` so that it
        is visible in the warnings summary of a normal pytest run (the
        configuration is loaded in a session-scoped fixture, whose
        captured stderr pytest only shows for failing tests). In
        strict mode both cases raise: a failed read, and credentials
        missing entirely (the most common way for Vault to be
        unavailable in an automated run is that the secret delivery
        mechanism failed to provide them).
        """
        flat_updates = {}
        section_updates = {}
        for path, value in self._iter_sentinel_values(self._settings.as_dict()):
            if path in _LIST_SETTINGS_PATHS:
                # the list-valued settings were resolved from their
                # effective value already: a sentinel that a higher
                # layer replaced is never resolved here
                continue
            resolved = self._resolve_value(value)
            if len(path) == 1:
                flat_updates[path[0]] = resolved
            else:
                section_updates.setdefault(path[0], []).append((path[1:], resolved))
        for name, value in flat_updates.items():
            self._settings.unset(name, force=True)
            if value is not _ABSENT:
                self._settings.set(name.upper(), value)
        for section, updates in section_updates.items():
            self._rewrite_section(section, updates)
        if not self._vault_failures:
            return
        # the diagnostics count the distinct unresolved sentinels of
        # the effective settings, and report each distinct failure
        # once, keeping the order
        count = len(self._vault_failures)
        failures = list(dict.fromkeys(self._vault_failures.values()))
        if not self._vault_resolver.configured:
            warnings.warn(
                "warning: {0} Vault sentinel value(s) in the settings are"
                " treated as absent: no Vault credentials (set VAULT_TOKEN,"
                " or VAULT_ROLE_ID and VAULT_SECRET_ID)".format(count)
            )
            if self._vault_resolver.strict:
                raise vault.VaultError(
                    "{0} Vault sentinel values could not be resolved: no"
                    " Vault credentials (set VAULT_TOKEN, or VAULT_ROLE_ID"
                    " and VAULT_SECRET_ID)".format(count)
                )
            return
        for failure in failures:
            warnings.warn("error: unresolved Vault sentinel: {0}".format(failure))
        if self._vault_resolver.strict:
            raise vault.VaultError(
                "{0} Vault sentinel values could not be resolved:\n"
                "{1}".format(count, "\n".join("- " + f for f in failures))
            )

    def _iter_sentinel_values(self, view, prefix=()):
        """
        Yield ``(path, value)`` for each settings value of the current
        environment that holds at least one sentinel, walking all the
        sections.

        Each value is read through its dotted path, which resolves to
        the effective value of the key (the one of the highest layer,
        environment variables included) and is case-insensitive on
        every supported dynaconf version. Walking the raw view instead
        would be wrong on dynaconf 3.1.5, whose store keeps case-variant
        spellings of the same key next to each other (for example the
        lowercase spelling of a settings file and the uppercase one of
        an environment variable): the stale file spelling of a sentinel
        would be resolved and written over the effective value of an
        explicitly-set environment variable, breaking its precedence,
        and a plain key defined by both a file sentinel and an
        environment variable would be counted twice.

        :param view: the settings (or a nested section of them) to walk
        :param prefix: the dotted path of ``view`` so far
        :type prefix: tuple
        """
        seen = set()
        for name in view:
            key = str(name).casefold()
            if key in seen:
                # a case-variant spelling of a key already walked: its
                # effective value has been read already
                continue
            seen.add(key)
            path = prefix + (key,)
            value = self._settings.get(".".join(path))
            if isinstance(value, dict):
                for item in self._iter_sentinel_values(value, path):
                    yield item
            elif vault.contains_sentinel(value):
                yield path, value

    def _resolve_value(self, value):
        """
        Resolve the sentinels of a settings value, element-wise for
        lists and for the dictionaries nested in them.

        :param value: the value to resolve
        :return: the resolved value; ``_ABSENT`` for a value holding
            unresolved sentinels — a scalar key is then removed, so
            that it behaves exactly as one that was never defined,
            and a list (or a dictionary or list nested in one) is
            removed as a whole
        """
        if not vault.contains_sentinel(value):
            return value
        if isinstance(value, list):
            resolved = []
            for element in value:
                resolved_element = self._resolve_list_element(element)
                if resolved_element is _ABSENT:
                    # a partially-resolved list must never be used
                    return _ABSENT
                resolved.append(resolved_element)
            return resolved
        if isinstance(value, dict):
            # only reachable for a dictionary nested in a list value:
            # the walker recurses into the dictionaries of the settings
            # themselves
            resolved = {}
            for name, element in value.items():
                resolved_element = self._resolve_list_element(element)
                if resolved_element is _ABSENT:
                    return _ABSENT
                resolved[name] = resolved_element
            return resolved
        return self._resolve_sentinel(value)

    def _resolve_sentinel(self, sentinel):
        """
        Resolve a single sentinel, remembering its failure.

        :param sentinel: the sentinel to resolve
        :return: the resolved value, or ``_ABSENT``
        """
        try:
            return self._vault_resolver.resolve(sentinel)
        except vault.VaultError as failure:
            # remember each distinct unresolved sentinel once, so that
            # the count of the diagnostics names exactly the distinct
            # unresolved sentinels of the effective settings
            self._vault_failures.setdefault(sentinel, str(failure))
            # an unresolved sentinel makes the key absent, exactly as
            # if it was never defined: an empty value is not absent
            # for keys like candlepin.org or insights.base_url, and a
            # partially-resolved value must never be used
            return _ABSENT

    def _resolve_list_element(self, element):
        """
        Resolve an element of a list value, or of a dictionary nested
        in one: any unresolved sentinel removes the whole containing
        list, as a partially-resolved value must never be used.

        :param element: the element to resolve
        :return: the resolved element, or ``_ABSENT``
        """
        if isinstance(element, (list, dict)):
            return self._resolve_value(element)
        if not vault.is_sentinel(element):
            return element
        return self._resolve_sentinel(element)

    def _rewrite_section(self, section, updates):
        """
        Write resolved values back into a top-level section of the
        settings, with a single spelling of each key.

        The section is rebuilt by reading each of its names through its
        dotted path, dropped, and set again as a whole: on dynaconf
        3.1.5 the store keeps case-variant duplicates of the same key
        (e.g. "password" and "PASSWORD") and only the dotted reads
        resolve to the effective values, so a plain ``set()`` of the
        single keys would leave the stale spellings in place.

        :param section: the name of the top-level section
        :param updates: list of ``(relative path, value)`` pairs to
            write, with ``_ABSENT`` meaning "remove the key"
        """
        plain = self._plain_value((section,))
        for relative_path, value in updates:
            node = plain
            for name in relative_path[:-1]:
                node = node.setdefault(name, {})
            if value is _ABSENT:
                node.pop(relative_path[-1], None)
            else:
                node[relative_path[-1]] = value
        self._settings.unset(section, force=True)
        self._settings.set(section.upper(), _uppercase_keys(plain), merge=False)

    def _plain_value(self, path):
        """
        A plain-dict view of a settings value, rebuilt through dotted
        reads so that the case-variant duplicates of dynaconf 3.1.5
        collapse to their effective values, with casefolded keys.

        :param path: the dotted path of the value
        :type path: tuple
        """
        value = self._settings.get(".".join(path))
        if not isinstance(value, dict):
            return value
        plain = {}
        for name in value:
            key = str(name).casefold()
            if key not in plain:
                plain[key] = self._plain_value(path + (key,))
        return plain

    def _effective_list_value(self, key):
        """
        The value a list-valued settings key should have, as a whole: the
        one of the highest layer that defines the key, that is the
        environment variable if set (an empty one counts as unset),
        otherwise the selected environment in the settings files (with
        .secrets.toml winning over settings.toml), otherwise [default].
        The sentinels of the value are resolved here, so that the
        comparison in _resolve_list_settings sees the value the key
        must end up with.
        """
        env_var = ENVVAR_PREFIX + "_" + key.upper().replace(".", "__")
        raw_value = os.environ.get(env_var)
        if raw_value is not None and raw_value.strip():
            value = parse_conf_data(
                boolean_fix(raw_value),
                tomlfy=True,
                box_settings=self._settings,
            )
            return self._absent_if_unresolved(self._resolve_value(value))
        # without ENV_FOR_DYNACONF the settings behave as if the default
        # environment was selected
        environments = (os.environ.get("ENV_FOR_DYNACONF", "default"), "default")
        for environment in environments:
            # the raw files are in increasing precedence order, so they are
            # read the other way around
            for raw_file in reversed(self._raw_files):
                value = raw_file.get("{}.{}".format(environment, key))
                if value is not None:
                    # the raw value can hold @vault sentinels: resolve
                    # them with the same semantics as the loaded
                    # settings, so that the comparison in
                    # _resolve_list_settings sees matching values
                    return self._absent_if_unresolved(self._resolve_value(value))
        return None

    @staticmethod
    def _absent_if_unresolved(value):
        """
        Turn the _ABSENT marker of the sentinel resolution into a plain
        missing value.
        """
        return None if value is _ABSENT else value

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
