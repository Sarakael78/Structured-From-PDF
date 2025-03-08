"""
Module for generating a dynamic prompt for the generative AI model using the provided configuration and legal text.
"""

from typing import Dict

def chunk_text(text: str, max_chunk_size: int = 4000) -> list[str]:
    """Break text into manageable chunks to avoid token limits."""
    # Simple implementation - split by paragraphs and combine until limit
    paragraphs = text.split("\n\n")
    chunks = []
    current_chunk = ""
    
    for paragraph in paragraphs:
        if len(current_chunk) + len(paragraph) > max_chunk_size:
            chunks.append(current_chunk)
            current_chunk = paragraph
        else:
            current_chunk += "\n\n" + paragraph if current_chunk else paragraph
            
    if current_chunk:
        chunks.append(current_chunk)
        
    return chunks

def generate_prompt(config: Dict, legal_text: str) -> str:
    """
    Generate a prompt for the AI model using configuration details and raw legal text.

    Args:
        config (Dict): Dictionary containing the configuration fields.
        legal_text (str): The legal judgment text to be analyzed.

    Returns:
        str: The complete prompt to send to the AI model.
    """
    schema_lines = []
    for field in config.get("fields", []):
        field_name = field.get("name", "unknown")
        field_type = field.get("type", "string")
        placeholder = f"<{field_type}>"
        schema_lines.append(f'    "{field_name}": "{placeholder}"')
    schema_str = "{\n" + ",\n".join(schema_lines) + "\n}"

    prompt = (
        "You are a highly capable AI model tasked with extracting structured data from the following text. "
        "Below is the required data format that must be strictly followed. Extract all relevant information and return it as valid JSON.\n\n"
        "### Structured Data Format:\n"
        f"{schema_str}\n\n"
        "### Text to Analyze:\n"
        f"{legal_text}\n\n"
        "Please return the output as a valid JSON object matching the above format."
    )
    return prompt