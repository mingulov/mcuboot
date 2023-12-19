# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import pytest

from click.testing import CliRunner
from imgtool import main as imgtool_main
from imgtool.main import imgtool
from intelhex import IntelHex

# all supported key types for 'keygen'
KEY_TYPES = [*imgtool_main.keygens]

# valid sign/encryption pairs
SIGN_ENC_KEY_TYPES = [
    ("rsa-2048", "rsa-2048"),
    ("rsa-3072", "rsa-2048"),
    ("ecdsa-p256", "ecdsa-p256"),
    ("ecdsa-p384", "ecdsa-p384"),
    ("ed25519", "x25519"),

    # 
    ("ed25519", "ed25519"),
    ("ed25519", "ecdsa-p256"),
    ("ed25519", "ecdsa-p384"),
    ("ed25519", "rsa-2048"),
    ("ed25519", "rsa-3072"),
    ("rsa-2048", "rsa-3072"),
    ("rsa-3072", "rsa-3072"),
]

SIGN_ONLY_KEY_TYPES = set([sign for (sign, _) in SIGN_ENC_KEY_TYPES])

ENC_ONLY_KEY_TYPES = set([enc for (_, enc) in SIGN_ENC_KEY_TYPES])

WRONG_SIGN_KEY_TYPES = list(set(KEY_TYPES) - set(SIGN_ONLY_KEY_TYPES))

# list of all images to test
IMAGES = {
    "00hdr.bin": { "size": 16383, "erased": 0x00, "header_0": 0x200, },
    "00hdr.hex": { "size": 16383, "erased": 0x00, "header_0": 0x200, },
    "00.bin": { "size": 16383, "erased": 0x00, },
    "00.hex": { "size": 16383, "erased": 0x00, },
    "ffhdr.bin": { "size": 16383, "erased": 0xff, "header_0": 0x200, },
    "ffhdr.hex": { "size": 16383, "erased": 0xff, "header_0": 0x200, },
    "ff.bin": { "size": 16383, "erased": 0xff, },
    "ff.hex": { "size": 16383, "erased": 0xff, },
}

ENC_KEY_EXT = ".enc.key"
SIGN_KEY_EXT = ".sign.key"
IMAGE_HEX_EXT = ".hex"
IMAGE_BLOCK_SIZE = 0x100

def tmp_name(tmp_path, file_type, suffix=""):
    return tmp_path / (file_type + suffix)


@pytest.fixture(scope="module")
def tmp_path_persistent(tmp_path_factory):
    return tmp_path_factory.mktemp("sign")


def sign_cmd_args(infile, outfile, sign_key, enc_key=None, 
                  header_size=0x200, slot_size=0x8000, version="1.0.0",
                  align=1, pad_header=None, load_addr=None, hex_addr=None):
    args = [
        "sign",
        "--key",
        str(sign_key),
        "--version",
        str(version),
        "--header-size",
        str(header_size),
        "--slot-size",
        str(slot_size),
    ]

    if enc_key is not None:
        args += [
            "--encrypt",
            str(enc_key),
        ]

    if align is not None:
        args += [
            "--align",
            str(align),
        ]

    if load_addr is not None:
        args += [
            "--load-addr",
            str(load_addr),
        ]

    if hex_addr is not None:
        args += [
            "--hex-addr",
            str(hex_addr),
        ]

    if pad_header:
        args += [
            "--pad-header",
        ]

    args += [
        str(infile),
        str(outfile),
    ]

    return args


def test_setup(tmp_path_persistent):
    """Setup initial files - keys and images"""
    runner = CliRunner()

    # generate all key types
    # to be used later for signing and encryption
    for key_type in KEY_TYPES:
        gen_key = tmp_name(tmp_path_persistent, key_type, SIGN_KEY_EXT)
        assert not gen_key.exists()
        result = runner.invoke(
            imgtool, ["keygen", "--key", str(gen_key), "--type", key_type]
        )
        assert result.exit_code == 0
        assert gen_key.exists()
        assert gen_key.stat().st_size > 0

        gen_key = tmp_name(tmp_path_persistent, key_type, ENC_KEY_EXT)
        assert not gen_key.exists()
        result = runner.invoke(
            imgtool, ["keygen", "--key", str(gen_key), "--type", key_type]
        )
        assert result.exit_code == 0
        assert gen_key.exists()
        assert gen_key.stat().st_size > 0

    # generate original images
    for img, data in IMAGES.items():
        size = data["size"]
        header_0 = data.get("header_0", 0)
        erased_val = data.get("erased", 0xff)
        image = tmp_name(tmp_path_persistent, img)

        ih = IntelHex()
        ih.padding = erased_val
        for i in range(header_0):
            ih[i] = 0
        for i in range(IMAGE_BLOCK_SIZE):
            # fill preventing 'erased val'
            ih[i + header_0] = 1 + i % 0xFE
            ih[size - i - 1] = 1 + i % 0xFE

        if image.suffix != IMAGE_HEX_EXT:
            ih.tofile(str(image), format='bin')
            assert image.exists()
            assert image.stat().st_size == size
        else:
            ih.tofile(str(image), format='hex')
            assert image.exists()


@pytest.mark.parametrize("image", IMAGES)
@pytest.mark.parametrize("key_type", WRONG_SIGN_KEY_TYPES)
def test_sign_wrong_key(image, key_type, tmp_path_persistent):
    """Test sign with an unsupported key type"""
    runner = CliRunner()

    sign_key = tmp_name(tmp_path_persistent, key_type, SIGN_KEY_EXT)
    image_in = tmp_name(tmp_path_persistent, image)
    image_signed = tmp_name(tmp_path_persistent, "image.signed")

    result = runner.invoke(
        imgtool,
        sign_cmd_args(image_in, image_signed, sign_key, pad_header=True),
    )
    assert result.exit_code != 0
    image_signed.unlink(True)


@pytest.mark.parametrize("image", IMAGES)
@pytest.mark.parametrize("sign_key_type", KEY_TYPES)
@pytest.mark.parametrize("enc_key_type", KEY_TYPES + [None])
def test_basic_sign_enc(image, sign_key_type, enc_key_type, tmp_path_persistent):
    """Test all possible sign/encryption key pairs"""
    runner = CliRunner()

    sign_key = tmp_name(tmp_path_persistent, sign_key_type, SIGN_KEY_EXT)
    enc_key = tmp_name(tmp_path_persistent, enc_key_type, ENC_KEY_EXT) if enc_key_type else None
    image_in = tmp_name(tmp_path_persistent, image)
    image_signed = tmp_name(tmp_path_persistent, "image.signed")

    image_signed.unlink(True)

    args = sign_cmd_args(image_in, image_signed, sign_key, enc_key=enc_key, pad_header=True)
    result = runner.invoke(
        imgtool,
        args,
    )

    if sign_key_type in SIGN_ONLY_KEY_TYPES and enc_key_type is None:
        # just signing
        assert result.exit_code == 0
    elif (sign_key_type, enc_key_type) in SIGN_ENC_KEY_TYPES:
        # encryption + signing
        assert result.exit_code == 0
    else:
        # some provided key is not ok
        assert result.exit_code != 0

    image_signed.unlink(True)


@pytest.mark.parametrize("image", IMAGES)
@pytest.mark.parametrize("sign_key_type", SIGN_ONLY_KEY_TYPES)
def test_sign_no_pad_header(image, sign_key_type, tmp_path_persistent):
    """Test --pad-header option"""
    runner = CliRunner()

    data = IMAGES[image]
    sign_key = tmp_name(tmp_path_persistent, sign_key_type, SIGN_KEY_EXT)
    image_in = tmp_name(tmp_path_persistent, image)
    image_signed = tmp_name(tmp_path_persistent, "image.signed")

    image_signed.unlink(True)

    args = sign_cmd_args(image_in, image_signed, sign_key, pad_header=False)
    result = runner.invoke(
        imgtool,
        args,
    )

    if data.get("header_0", 0) > 0:
        # Image should be fine
        assert result.exit_code == 0
    else:
        assert result.exit_code != 0

    image_signed.unlink(True)


@pytest.mark.parametrize("image", IMAGES)
@pytest.mark.parametrize("sign_key_type", SIGN_ONLY_KEY_TYPES)
def test_sign_hex_output(image, sign_key_type, tmp_path_persistent):
    """Test sign with hex output"""
    runner = CliRunner()

    data = IMAGES[image]
    sign_key = tmp_name(tmp_path_persistent, sign_key_type, SIGN_KEY_EXT)
    image_in = tmp_name(tmp_path_persistent, image)
    image_signed = tmp_name(tmp_path_persistent, "image.hex")

    image_signed.unlink(True)

    args = sign_cmd_args(image_in, image_signed, sign_key, pad_header=True, hex_addr=0x1000)
    result = runner.invoke(
        imgtool,
        args,
    )

    assert result.exit_code == 0

    args = sign_cmd_args(image_in, image_signed, sign_key, pad_header=True)
    result = runner.invoke(
        imgtool,
        args,
    )

    if image_in.suffix == IMAGE_HEX_EXT:
        assert result.exit_code == 0
    else:
        # for BIN image hex address must be specified to get HEX output
        assert result.exit_code != 0

    image_signed.unlink(True)
