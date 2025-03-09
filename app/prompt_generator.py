"""
Module for generating a dynamic prompt for the generative AI model using the provided configuration and legal text.
"""
import logging
from typing import Dict
import yaml

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

def generatePromptFromYaml(instructions: dict, legalText: str) -> str:
	"""
	Generate a prompt for the AI model using YAML instructions and raw legal text.

	Args:
		instructions (dict): YAML instructions defining required data structure.
		legalText (str): The legal judgment text to be analysed.

	Returns:
		str: The complete prompt to send to the AI model.
	"""
	yamlDefinitions = yaml.dump(instructions.get('yamlDefinitions', {}), sort_keys=False, indent=2)

	prompt = (
		f"You are a highly capable AI model tasked with extracting structured data from the following text.\n\n"
		f"### General Instructions:\n{instructions.get('llm', {}).get('general', '')}\n\n"
		f"### Output Format:\n{instructions.get('llm', {}).get('output', 'yaml format in a code block')}\n\n"
		f"### YAML Definitions:\n{yamlDefinitions}\n\n"
		f"### Additional Notes:\n{instructions.get('llm', {}).get('notes', '')}\n\n"
		f"### Text to Analyze:\n{legalText}\n\n"
		f"Please return the output strictly in YAML format enclosed within a code block."
	)
	return prompt

def generate_prompt(config: Dict, legal_text: str) -> str:
    # Try to load YAML instructions
    try:
        import yaml
        with open("instructions.yaml", "r", encoding="utf-8") as f:
            yaml_instructions = yaml.safe_load(f)
        if len(legal_text) > 4000:
            chunks = chunk_text(legal_text)
            logging.info(f"Text chunked into {len(chunks)} parts for processing")
            # Handle chunking logic
            legal_text = chunks[0]
    except Exception as e:
        logging.warning(f"Could not load YAML instructions: {e}")
        return _generate_schema_prompt(config, legal_text)  # Fallback


    # Extract components from YAML
    title = yaml_instructions.get("title", "Extracting Legal Information from Judgments")
    llm_instructions = yaml_instructions.get("llmInstructions", {})
    general_instruction = llm_instructions.get("general", "")
    notes = llm_instructions.get("notes", "")
    output_format = llm_instructions.get("output", "yaml format in a code block")
    
    # Convert YAML definitions to a string
    yaml_definitions = yaml_instructions.get("yamlDefinitions", [])
    yaml_str = yaml.dump(yaml_definitions, default_flow_style=False)
    
    # Assemble the complete prompt
    prompt = f"""# {title}
        ## YAML Structure for Extraction
        ```yaml
        {yaml_str}
        Instructions
        {general_instruction}
        Output Format
        {output_format}
        Notes
        {notes}
        Text to Analyze
        {legal_text}
        Please analyze the text and extract the requested information according to the YAML structure above. """ 
    return prompt

def _generate_schema_prompt(config: Dict, legal_text: str) -> str: 
    """Original schema-based prompt generation as fallback""" 
    schema_lines = [] 
    for field in config.get("fields", []): field_name = field.get("field_name", "unknown") 
    field_type = field.get("field_description", "string") 
    placeholder = f"<{field_type}>" 
    schema_lines.append(f' "{field_name}": "{placeholder}"') 
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




