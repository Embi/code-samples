# Copyright (C) 2018-2023 SpaceKnow, Inc.

from auth.oidc import oidc_client


def test_generate_code_verifier():
    code_verifier_a = oidc_client._generate_code_verifier()
    code_verifier_b = oidc_client._generate_code_verifier()

    assert isinstance(code_verifier_a, str)
    # 32-octet entropy must be at least 43 Base64 characters
    assert len(code_verifier_a) >= 43
    assert code_verifier_a != code_verifier_b


def test_generate_sha256_code_challenge():
    code_verifier = 'test-code-xxx'
    # SHA-256 HEX: D03E7D7F B8EA8DFE 1577AB56 D8DF6DA0 E47BE52E 50D121C3
    # D4244B99 D16BEF32
    # Base64: 0D59f7jqjf4Vd6tW2N9toOR75S5Q0SHD1CRLmdFr7zI=
    code_challenge = oidc_client._generate_sha256_code_challenge(code_verifier)
    assert code_challenge == '0D59f7jqjf4Vd6tW2N9toOR75S5Q0SHD1CRLmdFr7zI'
