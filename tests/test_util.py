# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import time
import pytest

from pytest_client_tools.util import redact_arguments, loop_until


@pytest.mark.parametrize(
    "args,redact_list,expected_args",
    [
        ([], [], []),
        (["a"], [], ["a"]),
        (["a", "--foo", "foo"], [], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], [], ["a", "--foo=foo"]),
        (["a", "--foo"], ["--foo"], ["a", "--foo"]),
        (["a", "--foo", "foo"], ["--foo"], ["a", "--foo", "<redacted>"]),
        (["a", "--foo", "foo"], ["--bar"], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], ["--foo"], ["a", "--foo=<redacted>"]),
        (["a", "--foo=foo"], ["--bar"], ["a", "--foo=foo"]),
        (["a", "--foo", "foo"], ["--unused", "--foo"], ["a", "--foo", "<redacted>"]),
        (["a", "--foo", "foo"], ["--unused", "--bar"], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], ["--unused", "--foo"], ["a", "--foo=<redacted>"]),
        (["a", "--foo=foo"], ["--unused", "--bar"], ["a", "--foo=foo"]),
        (["a", "--foobar", "foo"], ["--foo"], ["a", "--foobar", "foo"]),
        (["a", "--foobar=foo"], ["--foo"], ["a", "--foobar=foo"]),
        (["a", "--foo-bar", "foo"], ["--foo"], ["a", "--foo-bar", "foo"]),
        (["a", "--foo-bar=foo"], ["--foo"], ["a", "--foo-bar=foo"]),
    ],
)
def test_redact_arguments(args, redact_list, expected_args):
    assert redact_arguments(args, redact_list) == expected_args


class TestLoopUntil:
    """Test cases for the loop_until function."""

    def test_loop_until_success_immediate(self):
        """Test that loop_until returns True when predicate succeeds immediately."""
        result = loop_until(lambda: True, poll_sec=0.1, timeout_sec=1)
        assert result is True

    def test_loop_until_success_after_retries(self):
        """
        Test that loop_until returns True when predicate succeeds after some retries.
        """
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return counter >= 3

        start_time = time.time()
        result = loop_until(predicate, poll_sec=0.1, timeout_sec=2)
        elapsed_time = time.time() - start_time

        assert result is True
        assert counter == 3
        # Should take at least 2 polling intervals (0.2 seconds)
        assert elapsed_time >= 0.2

    def test_loop_until_timeout(self):
        """Test that loop_until returns False when predicate never succeeds."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return False

        start_time = time.time()
        result = loop_until(predicate, poll_sec=0.1, timeout_sec=0.5)
        elapsed_time = time.time() - start_time

        assert result is False
        # Should have been called multiple times
        assert counter > 1
        # Should respect the timeout
        assert elapsed_time >= 0.5
        assert elapsed_time < 1.0  # Should not exceed timeout significantly

    def test_loop_until_default_parameters(self):
        """Test loop_until with default parameters."""
        # This test uses a very short timeout to avoid long test execution
        result = loop_until(lambda: False, timeout_sec=0.1)
        assert result is False

    def test_loop_until_custom_poll_interval(self):
        """Test loop_until with custom polling interval."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return counter >= 2

        start_time = time.time()
        result = loop_until(predicate, poll_sec=0.2, timeout_sec=1)
        elapsed_time = time.time() - start_time

        assert result is True
        assert counter == 2
        # Should take at least one polling interval (0.2 seconds)
        assert elapsed_time >= 0.2

    def test_loop_until_predicate_exception(self):
        """Test that loop_until propagates exceptions from predicate."""

        def failing_predicate():
            raise ValueError("Test exception")

        with pytest.raises(ValueError, match="Test exception"):
            loop_until(failing_predicate, poll_sec=0.1, timeout_sec=0.5)

    def test_loop_until_zero_timeout(self):
        """Test loop_until behavior with zero timeout."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return False

        result = loop_until(predicate, poll_sec=0.1, timeout_sec=0)

        assert result is False
        # With zero timeout, the predicate should not be called
        # since the timeout condition fails immediately
        assert counter == 0

    def test_loop_until_realistic_scenario(self):
        """
        Test a realistic scenario similar to checking if insights-client is registered.
        """
        # Simulate a service that becomes "registered" after some time
        start_check_time = time.time()
        registration_delay = 0.3  # Service becomes ready after 0.3 seconds

        def is_service_ready():
            return time.time() - start_check_time >= registration_delay

        start_time = time.time()
        result = loop_until(is_service_ready, poll_sec=0.1, timeout_sec=1)
        elapsed_time = time.time() - start_time

        assert result is True
        # Should complete shortly after the registration delay
        assert elapsed_time >= registration_delay
        assert elapsed_time < registration_delay + 0.5
