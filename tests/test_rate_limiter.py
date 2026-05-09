"""
Tests for the GlobalRateLimiter and APIKeyPool.
"""

import asyncio
import os
import unittest
from unittest.mock import MagicMock, patch

# ── Test APIKeyPool ──────────────────────────────────────────


class TestAPIKeyPool(unittest.TestCase):
    """Test round-robin rotation, cooldown, and env var loading."""

    def setUp(self):
        # Reset the singleton between tests
        from src.utils.key_pool import APIKeyPool

        APIKeyPool._instance = None
        # The pool merges the singular fallback env var into the front of the
        # pool unconditionally, so clear it for tests that exercise pool-only
        # behaviour. CI sets GOOGLE_API_KEY=test-key by default.
        self._saved_single_key = os.environ.pop("GOOGLE_API_KEY", None)

    def tearDown(self):
        from src.utils.key_pool import APIKeyPool

        APIKeyPool._instance = None
        if self._saved_single_key is not None:
            os.environ["GOOGLE_API_KEY"] = self._saved_single_key

    @patch.dict(os.environ, {"GOOGLE_API_KEYS": "key_aaa,key_bbb,key_ccc"}, clear=False)
    def test_round_robin_rotation(self):
        from src.utils.key_pool import get_key_pool

        pool = get_key_pool()

        k1 = pool.get_key("gemini")
        k2 = pool.get_key("gemini")
        k3 = pool.get_key("gemini")
        k4 = pool.get_key("gemini")  # wraps around

        self.assertEqual(k1, "key_aaa")
        self.assertEqual(k2, "key_bbb")
        self.assertEqual(k3, "key_ccc")
        self.assertEqual(k4, "key_aaa")  # back to first

    @patch.dict(os.environ, {"GOOGLE_API_KEYS": "key_aaa,key_bbb,key_ccc"}, clear=False)
    def test_cooldown_skips_key(self):
        from src.utils.key_pool import get_key_pool

        pool = get_key_pool()

        # Get first key, then cool it down
        k1 = pool.get_key("gemini")
        self.assertEqual(k1, "key_aaa")

        pool.mark_cooldown("gemini", "key_aaa", duration_s=30.0)

        # Next call should skip key_aaa
        k2 = pool.get_key("gemini")
        self.assertEqual(k2, "key_bbb")

        k3 = pool.get_key("gemini")
        self.assertEqual(k3, "key_ccc")

        # Should skip key_aaa again
        k4 = pool.get_key("gemini")
        self.assertEqual(k4, "key_bbb")

    @patch.dict(os.environ, {"GOOGLE_API_KEY": "single_key_123"}, clear=False)
    def test_fallback_to_single_key(self):
        from src.utils.key_pool import get_key_pool

        # Ensure pool env var is NOT set
        os.environ.pop("GOOGLE_API_KEYS", None)
        pool = get_key_pool()

        k = pool.get_key("gemini")
        self.assertEqual(k, "single_key_123")

    @patch.dict(os.environ, {"GOOGLE_API_KEYS": "key_aaa"}, clear=False)
    def test_pool_status(self):
        from src.utils.key_pool import get_key_pool

        pool = get_key_pool()

        pool.get_key("gemini")
        status = pool.get_pool_status("gemini")

        self.assertEqual(status["total_keys"], 1)
        self.assertEqual(status["available_keys"], 1)
        self.assertEqual(status["keys"][0]["calls"], 1)

    @patch.dict(os.environ, {}, clear=False)
    def test_no_keys_raises(self):
        from src.utils.key_pool import get_key_pool

        os.environ.pop("GOOGLE_API_KEYS", None)
        os.environ.pop("GOOGLE_API_KEY", None)
        pool = get_key_pool()

        with self.assertRaises(ValueError):
            pool.get_key("gemini")


# ── Test GlobalRateLimiter ───────────────────────────────────


class TestGlobalRateLimiter(unittest.TestCase):
    """Test sliding-window RPM enforcement."""

    def setUp(self):
        from src.utils.rate_limiter import GlobalRateLimiter

        GlobalRateLimiter._instance = None

    def tearDown(self):
        from src.utils.rate_limiter import GlobalRateLimiter

        GlobalRateLimiter._instance = None

    @patch.dict(os.environ, {"RATE_LIMIT_RPM_OVERRIDE": "5"}, clear=False)
    def test_sync_acquire_blocks_at_limit(self):
        """Verify that acquire_sync hits the wait branch when RPM limit is reached."""
        from src.utils import rate_limiter as rl_mod
        from src.utils.rate_limiter import get_rate_limiter

        limiter = get_rate_limiter()

        # Fire 5 requests (the limit) — should be instant
        for _ in range(5):
            limiter.acquire_sync("test-model", "key1")

        # 6th request must enter the wait branch. The real wait is ~60s
        # (sliding window), so stub time.sleep to a no-op and assert it
        # was called with a positive duration.
        slept = []
        with patch.object(rl_mod.time, "sleep", side_effect=lambda s: slept.append(s)):
            limiter.acquire_sync("test-model", "key1")

        self.assertTrue(slept, "6th request should have entered the sleep branch")
        self.assertGreater(slept[0], 0.0)

    @patch.dict(os.environ, {"RATE_LIMIT_RPM_OVERRIDE": "5"}, clear=False)
    def test_async_acquire_blocks_at_limit(self):
        """Verify that async acquire hits the wait branch when RPM limit is reached."""
        from src.utils import rate_limiter as rl_mod
        from src.utils.rate_limiter import get_rate_limiter

        limiter = get_rate_limiter()

        slept = []

        async def fake_sleep(s):
            slept.append(s)

        async def _run():
            for _ in range(5):
                await limiter.acquire("test-model", "key1")
            with patch.object(rl_mod.asyncio, "sleep", side_effect=fake_sleep):
                await limiter.acquire("test-model", "key1")

        asyncio.run(_run())
        self.assertTrue(slept, "6th async request should have entered the sleep branch")
        self.assertGreater(slept[0], 0.0)

    def test_resolve_limits_gemini_flash(self):
        """Verify model limit resolution for known models."""
        from src.utils.rate_limiter import _resolve_limits

        with patch.dict(os.environ, {"RATE_LIMIT_TIER": "free"}, clear=False):
            # Clear the override if set
            os.environ.pop("RATE_LIMIT_RPM_OVERRIDE", None)
            limits = _resolve_limits("gemini-3-flash-preview")
            self.assertEqual(limits["rpm"], 10)
            self.assertEqual(limits["tpm"], 250_000)

    def test_resolve_limits_unknown_model(self):
        """Unknown models should get fallback limits."""
        from src.utils.rate_limiter import _resolve_limits

        os.environ.pop("RATE_LIMIT_RPM_OVERRIDE", None)
        limits = _resolve_limits("some-unknown-model-xyz")
        self.assertEqual(limits["rpm"], 10)  # fallback

    def test_status(self):
        """Verify get_status returns correct data."""
        from src.utils.rate_limiter import get_rate_limiter

        os.environ.pop("RATE_LIMIT_RPM_OVERRIDE", None)
        limiter = get_rate_limiter()
        limiter.acquire_sync("gemini-3-flash-preview", "testkey")
        status = limiter.get_status("gemini-3-flash-preview", "testkey")
        self.assertEqual(status["rpm_used"], 1)
        self.assertGreater(status["rpm_remaining"], 0)


# ── Test RateLimitedLLM Wrapper ──────────────────────────────


class TestRateLimitedLLM(unittest.TestCase):
    """Test the LLM wrapper's invoke/ainvoke interception."""

    def setUp(self):
        from src.utils.key_pool import APIKeyPool
        from src.utils.rate_limiter import GlobalRateLimiter

        GlobalRateLimiter._instance = None
        APIKeyPool._instance = None
        # CI sets GOOGLE_API_KEY=test-key; the pool merges it as the priority
        # key, which would shadow any pool-scoped fixture set up below.
        self._saved_single_key = os.environ.pop("GOOGLE_API_KEY", None)

    def tearDown(self):
        from src.utils.key_pool import APIKeyPool
        from src.utils.rate_limiter import GlobalRateLimiter

        GlobalRateLimiter._instance = None
        APIKeyPool._instance = None
        if self._saved_single_key is not None:
            os.environ["GOOGLE_API_KEY"] = self._saved_single_key

    @patch.dict(os.environ, {"RATE_LIMIT_RPM_OVERRIDE": "100"}, clear=False)
    def test_invoke_delegates_to_llm(self):
        """Verify that .invoke() calls the underlying LLM."""
        from src.utils.rate_limiter import RateLimitedLLM, get_rate_limiter

        mock_llm = MagicMock()
        mock_llm.model = "gemini-3-flash-preview"
        mock_llm.invoke.return_value = "response_text"

        wrapper = RateLimitedLLM(
            llm=mock_llm,
            limiter=get_rate_limiter(),
            model_name="gemini-3-flash-preview",
        )
        result = wrapper.invoke("test prompt")

        self.assertEqual(result, "response_text")
        mock_llm.invoke.assert_called_once_with("test prompt")

    @patch.dict(os.environ, {"RATE_LIMIT_RPM_OVERRIDE": "100"}, clear=False)
    def test_ainvoke_delegates_to_llm(self):
        """Verify that .ainvoke() calls the underlying LLM."""
        from src.utils.rate_limiter import RateLimitedLLM, get_rate_limiter

        mock_llm = MagicMock()
        mock_llm.model = "gemini-3-flash-preview"

        async def mock_ainvoke(*args, **kwargs):
            return "async_response"

        mock_llm.ainvoke = mock_ainvoke

        wrapper = RateLimitedLLM(
            llm=mock_llm,
            limiter=get_rate_limiter(),
            model_name="gemini-3-flash-preview",
        )

        result = asyncio.run(wrapper.ainvoke("test prompt"))
        self.assertEqual(result, "async_response")

    @patch.dict(
        os.environ,
        {
            "RATE_LIMIT_RPM_OVERRIDE": "100",
            "GOOGLE_API_KEYS": "key_111,key_222",
        },
        clear=False,
    )
    def test_429_triggers_key_rotation(self):
        """Verify that a 429 error triggers key cooldown and retry."""
        from src.utils.key_pool import get_key_pool
        from src.utils.rate_limiter import RateLimitedLLM, get_rate_limiter

        pool = get_key_pool()
        initial_key = pool.get_key("gemini")

        mock_llm = MagicMock()
        mock_llm.model = "gemini-3-flash-preview"
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("429 Resource Exhausted: quota exceeded")
            return "success_after_retry"

        mock_llm.invoke.side_effect = side_effect

        wrapper = RateLimitedLLM(
            llm=mock_llm,
            limiter=get_rate_limiter(),
            key_pool=pool,
            provider="gemini",
            model_name="gemini-3-flash-preview",
        )
        wrapper.set_key(initial_key)

        result = wrapper.invoke("test")
        self.assertEqual(result, "success_after_retry")
        self.assertEqual(call_count, 2)

    @patch.dict(os.environ, {"RATE_LIMIT_RPM_OVERRIDE": "100"}, clear=False)
    def test_attribute_proxy(self):
        """Verify that unknown attributes are proxied to the underlying LLM."""
        from src.utils.rate_limiter import RateLimitedLLM, get_rate_limiter

        mock_llm = MagicMock()
        mock_llm.model = "gemini-3-flash-preview"
        mock_llm.some_custom_attr = "hello"

        wrapper = RateLimitedLLM(
            llm=mock_llm,
            limiter=get_rate_limiter(),
            model_name="gemini-3-flash-preview",
        )
        self.assertEqual(wrapper.some_custom_attr, "hello")


if __name__ == "__main__":
    unittest.main()
