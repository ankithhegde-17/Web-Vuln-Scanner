"""LLM providers behind one small, provider-agnostic interface.

The rest of the triage code only ever calls `provider.complete(system, user)`
and gets back a string. Swapping Claude for another model is just a different
`LLMProvider` subclass, so the engine never hard-codes a vendor.

Key handling (the important safety part):
  * API keys are read ONLY from the environment (or a local .env that we load
    into the environment). They never appear in code, in arguments, or in any
    output file.
  * If the key is missing we raise MissingAPIKey, which the callers turn into a
    graceful "skipping triage" message -- never a crash, and nothing is sent.
  * The vendor SDK (anthropic / openai) is imported lazily inside each provider
    so the core scanner has no dependency on them at all.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path


class TriageError(Exception):
    """Any problem while triaging (SDK missing, bad response, ...)."""


class MissingAPIKey(TriageError):
    """No API key is configured for the chosen provider.

    Carries the env var name so the caller can tell the user exactly what to
    set. This is the 'skip gracefully' signal, not a real error.
    """

    def __init__(self, env_var: str, provider: str):
        self.env_var = env_var
        self.provider = provider
        super().__init__(f"No API key for provider '{provider}': set {env_var} (env var or .env file).")


def load_dotenv(path: str | Path = ".env") -> list[str]:
    """Minimal .env loader (so we don't add python-dotenv just for this).

    Reads KEY=VALUE lines from `path` and copies them into os.environ, but
    never overwrites a variable that is already set (an explicitly exported
    env var wins over the file). Lines that are blank, comments, or malformed
    are skipped. Returns the names of the keys it loaded, for logging -- never
    the values.
    """
    env_path = Path(path)
    loaded: list[str] = []
    if not env_path.is_file():
        return loaded
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")  # tolerate quoted values
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


class LLMProvider(ABC):
    """One text-in/text-out model call."""

    name: str = "base"
    api_key_env: str = ""
    default_model: str = ""

    def __init__(self, model: str | None = None):
        self.model = model or self.default_model

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Send one prompt and return the model's text response."""


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    api_key_env = "ANTHROPIC_API_KEY"
    # Sonnet is the cost/quality sweet spot for a classification-style triage
    # task; override with --llm-model for a bigger or smaller model.
    default_model = "claude-sonnet-5-5"

    def complete(self, system: str, user: str) -> str:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the SDK
            raise TriageError(
                "The 'anthropic' package is required for Claude triage. "
                "Install it with: pip install -r requirements-triage.txt"
            ) from exc

        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment
        message = client.messages.create(
            model=self.model,
            max_tokens=8000,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Concatenate the text blocks of the response (ignore any thinking blocks).
        return "".join(block.text for block in message.content if getattr(block, "type", None) == "text")


class OpenAIProvider(LLMProvider):
    name = "openai"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"

    def complete(self, system: str, user: str) -> str:
        try:
            import openai
        except ImportError as exc:  # pragma: no cover
            raise TriageError(
                "The 'openai' package is required for OpenAI triage. "
                "Install it with: pip install -r requirements-triage.txt"
            ) from exc

        client = openai.OpenAI()  # reads OPENAI_API_KEY from the environment
        resp = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return resp.choices[0].message.content or ""


class GeminiProvider(LLMProvider):
    name = "gemini"
    api_key_env = "GEMINI_API_KEY"
    # gemini-3.8-flash is the current stable Flash model (fast + cheap, which
    # suits a classification-style triage task). Override with --llm-model.
    default_model = "gemini-3.8-flash"

    def complete(self, system: str, user: str) -> str:
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - exercised only without the SDK
            raise TriageError(
                "The 'google-genai' package is required for Gemini triage. "
                "Install it with: pip install -r requirements-triage.txt"
            ) from exc

        # genai.Client() picks up GEMINI_API_KEY from the environment on its own.
        # (If GOOGLE_API_KEY is also set, the SDK prefers it -- so we read only
        # GEMINI_API_KEY here, matching api_key_env and the build_provider check.)
        client = genai.Client()
        resp = client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(system_instruction=system),
        )
        # response.text concatenates the text parts; it can be None if the model
        # returned no text (e.g. a safety block), so coerce to a string.
        return resp.text or ""


PROVIDERS: dict[str, type[LLMProvider]] = {
    AnthropicProvider.name: AnthropicProvider,
    OpenAIProvider.name: OpenAIProvider,
    GeminiProvider.name: GeminiProvider,
}


def build_provider(name: str = "anthropic", model: str | None = None) -> LLMProvider:
    """Create a provider, after confirming its API key is present.

    Raises:
        TriageError:   unknown provider name.
        MissingAPIKey: the provider's key env var is not set (callers treat
                       this as 'skip triage', not a failure).

    The key presence check happens here, before the vendor SDK is imported or
    any network call is made, so "no key" never reaches the provider.
    """
    provider_cls = PROVIDERS.get(name.lower())
    if provider_cls is None:
        known = ", ".join(sorted(PROVIDERS))
        raise TriageError(f"Unknown LLM provider '{name}'. Available: {known}.")

    if not os.environ.get(provider_cls.api_key_env):
        raise MissingAPIKey(provider_cls.api_key_env, provider_cls.name)

    return provider_cls(model=model)
