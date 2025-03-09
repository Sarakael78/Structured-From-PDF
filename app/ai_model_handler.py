# ai_model_handler.py (enhanced)
"""
Module for interfacing with multiple generative AI models.
"""

import logging
from typing import Dict, Any, List, Optional
import google.generativeai as palm  # Google AI
from openai import OpenAI  # Modern import
from utils import retry_with_backoff
import openai   

class ModelFactory:
    """Factory class for creating model handlers based on provider"""

    @staticmethod
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def get_model_handler(provider: str):
        """Return the appropriate model handler for the given provider"""
        handlers = {
            "google": GoogleAIHandler(),
            "openai": OpenAIHandler(),
            # Add more handlers as needed
        }
        return handlers.get(provider)


class ModelHandler:
    """Base class for model handlers"""
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def call_model(self, prompt: str, api_key: str, model_name: str, **kwargs) -> str:
        """Call the model with the given prompt and parameters"""
        raise NotImplementedError("Subclasses must implement call_model")
    
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def get_available_models(self, api_key: str) -> List[str]:
        """Return a list of available models for this provider"""
        raise NotImplementedError("Subclasses must implement get_available_models")


class GoogleAIHandler(ModelHandler):
    """Handler for Google Generative AI models"""
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def call_model(self, prompt: str, api_key: str, model_name: str, **kwargs) -> str:
        """Call Google's generative AI model"""
        palm.configure(api_key=api_key)

        try:
            temperature = kwargs.get("temperature", 0.0)
            response = palm.generate_text(
                model=model_name,
                prompt=prompt,
                temperature=temperature,
            )

            if response is None or not hasattr(response, "result"):
                raise ValueError("No valid response received from the AI API")

            return response.result
        except Exception as e:
            logging.error("Error calling Google AI model: %s", e)
            raise
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def get_available_models(self, api_key: str) -> List[str]:
        """Get available Google AI models"""
        palm.configure(api_key=api_key)
        try:
            models = palm.list_models()
            return [model.name for model in models if "generateText" in model.supported_generation_methods]
        except palm.GenerativeAIError as e:
            logging.error("Error retrieving Google AI models: %s", e)
            return ["models/text-bison-001", "models/gemini-pro"]  # Provide some defaults


class OpenAIHandler(ModelHandler):
    """Handler for OpenAI models"""
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    # In OpenAIHandler class, update to client-based approach:
    def call_model(self, prompt: str, api_key: str, model_name: str, **kwargs) -> str:
        """Call OpenAI model using the newer client-based API"""

        
        client = OpenAI(api_key=api_key)
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get("temperature", 0.0),
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error("Error calling OpenAI model: %s", e)
            raise
    # Then apply to API calls in ai_model_handler.py:
    @retry_with_backoff(max_retries=3)
    def get_available_models(self, api_key: str) -> List[str]:
        """Get available OpenAI models"""
        openai.api_key = api_key
        try:
            models = openai.Model.list()
            return [model.id for model in models.data]
        except openai.OpenAIError as e:
            logging.error("Error retrieving OpenAI models: %s", e)
            return ["gpt-4", "gpt-3.5-turbo"]  # Provide some defaults


# Main function to call AI models
# Then apply to API calls in ai_model_handler.py:
@retry_with_backoff(max_retries=3)
def call_ai_model(prompt: str, api_key: str, model_name: str, **kwargs) -> str:
    """
    Call an AI model with the given prompt and parameters.
    Automatically detects which provider to use based on the model name.

    Args:
        prompt (str): The prompt text for the AI model.
        api_key (str): API key for authentication.
        model_name (str): The model name to use.
        **kwargs: Additional parameters to pass to the model.

    Returns:
        str: The generated text from the AI model.
    """
    # Provider mapping (can be moved to a configuration file)
    provider_mapping = {
        "google": ["gemini", "models/text-bison-001"],
        "openai": ["gpt", "text-davinci"],
    }

    # Determine provider based on model name
    provider = None
    for p, model_prefixes in provider_mapping.items():
        for prefix in model_prefixes:
            if model_name.startswith(prefix):
                provider = p
                break
        if provider:
            break

    if not provider:
        raise ValueError(f"Unsupported model name: {model_name}")

    # Get the appropriate handler and call the model
    handler = ModelFactory.get_model_handler(provider)
    if not handler:
        raise ValueError(f"No handler found for provider: {provider}")

    try:
        return handler.call_model(prompt, api_key, model_name, **kwargs)
    except Exception as e:
        logging.error("Error calling AI model: %s", e)
        raise

# Then apply to API calls in ai_model_handler.py:
@retry_with_backoff(max_retries=3)
def get_available_models(api_key: str, provider: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Get available models from one or all providers.

    Args:
        api_key (str): API key for authentication.
        provider (Optional[str]): Specific provider to query, or None for all.

    Returns:
        Dict[str, List[str]]: Dictionary of provider names to lists of model names.
    """
    result = {}
    providers = ["google", "openai"] if provider is None else [provider]

    for p in providers:
        try:
            handler = ModelFactory.get_model_handler(p)
            if handler:
                result[p] = handler.get_available_models(api_key)
        except Exception as e:
            logging.error(f"Error retrieving models for provider {p}: {e}")
            result[p] = []

    return result