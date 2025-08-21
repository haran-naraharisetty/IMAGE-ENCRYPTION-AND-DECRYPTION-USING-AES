import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import io

st.title(" AES Image Encryption & Decryption")

# Encryption function
def encrypt_image(image_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(image_data, AES.block_size))

# Decryption function
def decrypt_image(cipher_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_data), AES.block_size)

# === ENCRYPT SECTION ===
st.header("️ Encrypt Image")

uploaded_file = st.file_uploader("Upload an Image to Encrypt", type=["png", "jpg", "jpeg"])

if uploaded_file:
    image = Image.open(uploaded_file).convert("RGB")
    st.image(image, caption="Original Image", use_column_width=True)
    img_array = np.array(image)
    img_bytes = img_array.tobytes()

    # Generate key and IV
    key = get_random_bytes(16)  # 16 bytes for AES-128
    iv = get_random_bytes(16)

    if st.button(" Encrypt and Download"):
        encrypted_data = encrypt_image(img_bytes, key, iv)

        # Save shape, IV, and encrypted data together
        shape_bytes = np.array(img_array.shape, dtype=np.int32).tobytes()
        combined_data = shape_bytes + iv + encrypted_data

        # Prepare encrypted file
        encrypted_file = io.BytesIO(combined_data)
        encrypted_file.seek(0)

        st.download_button(
            label="⬇️ Download Encrypted File",
            data=encrypted_file,
            file_name="encrypted_image.bin",
            mime="application/octet-stream"
        )

        # Display the AES key
        st.subheader(" Copy and Save this AES Key (Hex Format)")
        st.code(key.hex(), language="text")
        st.info("You'll need this key to decrypt the image later. Keep it secure!")

# === DECRYPT SECTION ===
st.header(" Decrypt Encrypted File")

uploaded_encrypted_file = st.file_uploader("Upload Encrypted `.bin` File", type=["bin"], key="decrypt")

key_hex_input = st.text_input(" Paste the 32-character (16-byte) AES key (in hex format)")

if uploaded_encrypted_file and key_hex_input:
    try:
        # Read encrypted binary content
        bin_data = uploaded_encrypted_file.read()
        shape = np.frombuffer(bin_data[:12], dtype=np.int32)
        iv = bin_data[12:28]
        encrypted_img_data = bin_data[28:]

        # Convert key from hex input
        key = bytes.fromhex(key_hex_input.strip())
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes (32 hex characters)")

        # Decrypt image
        decrypted_bytes = decrypt_image(encrypted_img_data, key, iv)
        decrypted_array = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(*shape)

        st.image(decrypted_array, caption="️ Decrypted Image", use_column_width=True)

    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
