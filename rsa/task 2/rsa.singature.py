import base64
import json
import requests
import math


def json_to_cookie(data: str) -> str:
    """Encode JSON data into a cookie-friendly format using base64."""
    json_bytes = data.encode()
    base64_bytes = base64.b64encode(json_bytes, altchars=b"-_")
    return base64_bytes.decode()


def cookie_to_json(cookie_data: str) -> str:
    """Decode JSON data from a cookie-friendly format using base64."""
    base64_bytes = cookie_data.encode()
    json_bytes = base64.b64decode(base64_bytes, altchars=b"-_")
    return json_bytes.decode()


def get_signed_document(data, base_url):
    """Obtain a signed message from the server."""
    try:
        response = requests.get(f"{base_url}/sign_random_document_for_students/{data}")
        response.raise_for_status()  # Raise an exception for HTTP errors (e.g., 404, 500)
        return response.json()  # Try to parse response as JSON
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Error retrieving signed document: {e}")
        print(f"Response content: {response.content}")
        return None


def get_modulus(base_url):
    """Get the modulus N from the server."""
    try:
        response = requests.get(f"{base_url}/pk/")
        response.raise_for_status()
        modulus_data = response.json()
        return modulus_data["N"]
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        print(f"Error retrieving modulus data: {e}")
        return None


def multiply_signatures(signature1, signature2, N):
    """Multiply two RSA signatures."""
    x1 = int.from_bytes(signature1, "big")
    x2 = int.from_bytes(signature2, "big")
    new_signature_int = (x1 * x2) % N
    return new_signature_int.to_bytes(math.ceil(int.bit_length(N) / 8), "big")


def main():
    base_url = input("Enter the base URL: ")

    N = get_modulus(base_url)
    original_message = "You got a 12 because you are an excellent student! :)"

    # Encode the message and convert it to hexadecimal
    encoded_original_message = original_message.encode()

    # Convert the original message to an integer and divide by 5
    original_message_int = int.from_bytes(encoded_original_message, "big")
    message1_int = original_message_int // 5
    message2_int = 5

    # Get the modulus from the server
    modulus = get_modulus(base_url)

    if not modulus:
        print("Failed to obtain modulus.")
        return

    n_bytes = math.ceil(int.bit_length(N) / 8)
    encoded_message1 = message1_int.to_bytes(n_bytes, "big")
    encoded_message2 = message2_int.to_bytes(n_bytes, "big")

    # Obtain signatures for both the original and modified messages
    signature1 = get_signed_document(encoded_message1.hex(), base_url).get("signature")
    signature2 = get_signed_document(encoded_message2.hex(), base_url).get("signature")

    if not signature1 or not signature2:
        print("Failed to obtain signatures for both messages.")
        return

    # Multiply the signatures to obtain the desired signature
    forged_signature = multiply_signatures(
        bytes.fromhex(signature1), bytes.fromhex(signature2), N
    )

    # Craft a JSON object with the forged signature
    forged_json_data = json.dumps(
        {"msg": encoded_original_message.hex(), "signature": forged_signature.hex()}
    )

    # Encode JSON data into a cookie-friendly format
    forged_cookie_data = json_to_cookie(forged_json_data)

    # Send the forged cookie to the server using /grade instead of /quote
    response = requests.get(f"{base_url}/grade/", cookies={"grade": forged_cookie_data})
    print(response.text)


if __name__ == "__main__":
    main()
