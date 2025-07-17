
from openai import OpenAI
import json
import re
import os
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from urllib.parse import urlparse
import uuid
import requests

client = OpenAI()

# Tool 1: Generate a social media post (text)
def generate_text_post(platform, audience, description):
    print(audience)
    return f"({platform}) post for {audience}: {description}"

# Tool 2: Generate an image for a post
def generate_image(description):
    response = client.images.generate(
        model="dall-e-3",
        prompt=description,
        n=1,
        size="1024x1024"
    )
    image_url = response.data[0].url

    # Download the image
    img_response = requests.get(image_url)
    if img_response.status_code == 200:
        # Create a unique filename
        ext = os.path.splitext(urlparse(image_url).path)[-1] or ".png"
        filename = f"ai_images/{uuid.uuid4().hex}{ext}"
        # Save to MEDIA_ROOT
        file_path = default_storage.save(filename, ContentFile(img_response.content))
        # Build the media URL
        media_url = os.path.join(settings.MEDIA_URL, file_path)
        return media_url
    else:
        raise Exception("Failed to download image from OpenAI.")

def get_tool_schema(name, description, parameters):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters
        }
    }

# Register tools for OpenAI function calling
tools = [
    get_tool_schema(
        name="generate_text_post",
        description="Generate a social media post.",
        parameters={
            "type": "object",
            "properties": {
                "platform": {"type": "string"},
                "audience": {"type": "string"},
                "description": {"type": "string"}
            },
            "required": ["platform", "audience", "description"]
        }
    ),
    get_tool_schema(
        name="generate_image",
        description="Generate an image for a post.",
        parameters={
            "type": "object",
            "properties": {
                "description": {"type": "string"}
            },
            "required": ["description"]
        }
    )
]

def ai_agent(messages, tools=None,temperature=0.7):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        temperature=temperature,
        tools=tools,
        tool_choice="auto"
    )
    message = response.choices[0].message

    # If a tool is called, run the corresponding Python function
    print(message.tool_calls[0],'dsa')
    if message.tool_calls:
        tool_call = message.tool_calls[0]
        function_name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)

        if function_name == "generate_text_post":
            result = generate_text_post(**args)
            return {"type": "text", "content": result}

        elif function_name == "generate_image":
            result = generate_image(**args)
            return {"type": "image", "url": result}

    return {"type": "text", "content": message.content}


# ai_agent('Which remote work tools are most popular among teams?')
def sanitize_input(text):
    """
    Removes *, -, /, and similar characters from the given text.
    """
    if isinstance(text, str):
        return re.sub(r'[*\-\/]', '', text)
    return text