#!/usr/bin/env perl
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

# Unit tests for the PasskeyAuth WebAuthn module.
# These test the cryptographic primitives and protocol logic in isolation,
# without requiring a running Bugzilla instance or database.

use strict;
use warnings;
use 5.10.1;
use lib qw( . lib local/lib/perl5 );
use File::Spec;

# Hook @INC to resolve Bugzilla::Extension:: modules the same way Bugzilla does,
# mapping Bugzilla/Extension/Foo/Bar.pm -> extensions/Foo/lib/Bar.pm
BEGIN {
  push @INC, sub {
    my (undef, $file) = @_;
    my @parts = File::Spec->splitdir($file);
    if (@parts > 3 && $parts[0] eq 'Bugzilla' && $parts[1] eq 'Extension') {
      my $ext = $parts[2];
      my @rest = @parts[3 .. $#parts];
      my $real = File::Spec->catfile('extensions', $ext, 'lib', @rest);
      if (-f $real) {
        open my $fh, '<', $real or return;
        $INC{$file} = $real;
        return $fh;
      }
    }
    return;
  };
}

use Test2::V0;
use CBOR::PP     ();
use Crypt::PK::ECC;
use Crypt::PRNG  qw(random_bytes);
use Crypt::Digest::SHA256 qw(sha256);
use MIME::Base64  qw(encode_base64 decode_base64);
use JSON::XS     ();

# -- Stub out Bugzilla::Error so ThrowUserError/ThrowCodeError die with
#    a testable message instead of trying to load Bugzilla's template system.
BEGIN {
  package Bugzilla::Error;
  use Exporter qw(import);
  our @EXPORT = qw(ThrowUserError ThrowCodeError);
  sub ThrowUserError {
    my ($err, $vars) = @_;
    my $msg = "USER_ERROR: $err";
    $msg .= " ($vars->{reason})" if ref $vars eq 'HASH' && $vars->{reason};
    die "$msg\n";
  }
  sub ThrowCodeError {
    my ($err, $vars) = @_;
    my $msg = "CODE_ERROR: $err";
    $msg .= " ($vars->{param})" if ref $vars eq 'HASH' && $vars->{param};
    die "$msg\n";
  }
  $INC{'Bugzilla/Error.pm'} = __FILE__;
}

use Bugzilla::Extension::PasskeyAuth::WebAuthn;

# -- Base64url helper tests ---------------------------------------------------

subtest 'base64url round-trip' => sub {
  my @test_data = (
    '',
    "\x00",
    "\x00\x01\x02",
    random_bytes(32),
    random_bytes(64),
    # Data that exercises +, /, and = padding in standard base64
    "\xfb\xff\xfe",
  );

  for my $data (@test_data) {
    my $encoded = Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($data);
    my $decoded = Bugzilla::Extension::PasskeyAuth::WebAuthn::_decode_b64url($encoded);
    is($decoded, $data, "round-trip for " . length($data) . " bytes");

    # Verify no forbidden characters in base64url output
    unlike($encoded, qr/[+\/=]/, "no standard base64 chars in output");
  }
};

# -- COSE key to PEM conversion tests ----------------------------------------

subtest 'COSE ES256 key to PEM' => sub {
  # Generate a real P-256 key pair
  my $pk = Crypt::PK::ECC->new();
  $pk->generate_key('nistp256');

  # Export the raw public key point (uncompressed: 0x04 || x || y)
  my $pub_raw = $pk->export_key_raw('public');
  my $x = substr($pub_raw, 1, 32);
  my $y = substr($pub_raw, 33, 32);

  # Build a COSE key map (ES256 = alg -7, P-256 = crv 1, EC2 = kty 2)
  my $cose_key = {
    1  => 2,    # kty = EC2
    3  => -7,   # alg = ES256
    -1 => 1,    # crv = P-256
    -2 => $x,
    -3 => $y,
  };

  my $pem = Bugzilla::Extension::PasskeyAuth::WebAuthn::_cose_key_to_pem($cose_key);

  # Verify it's valid PEM
  like($pem, qr/-----BEGIN PUBLIC KEY-----/, "PEM starts correctly");
  like($pem, qr/-----END PUBLIC KEY-----/,   "PEM ends correctly");

  # Import the PEM and verify it matches the original key
  my $reimported = Crypt::PK::ECC->new(\$pem);
  my $reimported_raw = $reimported->export_key_raw('public');
  is($reimported_raw, $pub_raw, "reimported key matches original");
};

subtest 'COSE key rejects unsupported algorithms' => sub {
  # RSA key type (kty=3) should be rejected
  my $rsa_cose = {1 => 3, 3 => -257, -1 => 1, -2 => 'x', -3 => 'y'};
  like(
    dies { Bugzilla::Extension::PasskeyAuth::WebAuthn::_cose_key_to_pem($rsa_cose) },
    qr/unsupported key type/,
    "rejects RSA key type"
  );

  # Wrong curve (P-384 = crv 2)
  my $wrong_curve = {1 => 2, 3 => -7, -1 => 2, -2 => 'x', -3 => 'y'};
  like(
    dies { Bugzilla::Extension::PasskeyAuth::WebAuthn::_cose_key_to_pem($wrong_curve) },
    qr/unsupported curve/,
    "rejects P-384 curve"
  );

  # Missing coordinates
  my $no_coords = {1 => 2, 3 => -7, -1 => 1};
  like(
    dies { Bugzilla::Extension::PasskeyAuth::WebAuthn::_cose_key_to_pem($no_coords) },
    qr/missing key coordinates/,
    "rejects missing coordinates"
  );
};

# -- Authenticator data parsing tests -----------------------------------------

subtest 'parse_auth_data - minimal (no attested credential)' => sub {
  my $rp_id_hash = sha256("example.com");
  my $flags = 0x01;  # user present
  my $sign_count = 42;

  my $auth_data = $rp_id_hash . pack('C', $flags) . pack('N', $sign_count);

  my $parsed = Bugzilla::Extension::PasskeyAuth::WebAuthn::_parse_auth_data($auth_data);

  is($parsed->{rp_id_hash}, $rp_id_hash, "rp_id_hash parsed correctly");
  is($parsed->{flags}, $flags, "flags parsed correctly");
  is($parsed->{sign_count}, $sign_count, "sign_count parsed correctly");
  ok(!exists $parsed->{attested_credential}, "no attested credential");
};

subtest 'parse_auth_data - with attested credential' => sub {
  my $rp_id_hash = sha256("example.com");
  my $flags = 0x41;  # user present + attested credential data
  my $sign_count = 1;
  my $aaguid = "\x00" x 16;
  my $credential_id = random_bytes(32);

  # Generate a real key for the COSE public key
  my $pk = Crypt::PK::ECC->new();
  $pk->generate_key('nistp256');
  my $pub_raw = $pk->export_key_raw('public');
  my $x = substr($pub_raw, 1, 32);
  my $y = substr($pub_raw, 33, 32);

  my $cose_key = {1 => 2, 3 => -7, -1 => 1, -2 => $x, -3 => $y};
  my $cose_cbor = CBOR::PP::encode($cose_key);

  my $auth_data = $rp_id_hash
    . pack('C', $flags)
    . pack('N', $sign_count)
    . $aaguid
    . pack('n', length($credential_id))
    . $credential_id
    . $cose_cbor;

  my $parsed = Bugzilla::Extension::PasskeyAuth::WebAuthn::_parse_auth_data($auth_data);

  is($parsed->{rp_id_hash}, $rp_id_hash, "rp_id_hash correct");
  is($parsed->{flags}, $flags, "flags correct");
  is($parsed->{sign_count}, $sign_count, "sign_count correct");
  ok(exists $parsed->{attested_credential}, "attested credential present");
  is($parsed->{attested_credential}{credential_id}, $credential_id,
    "credential_id correct");
  is($parsed->{attested_credential}{aaguid}, $aaguid, "aaguid correct");

  # Verify the COSE key was decoded
  my $decoded_cose = $parsed->{attested_credential}{public_key};
  is($decoded_cose->{1}, 2,  "COSE kty correct");
  is($decoded_cose->{3}, -7, "COSE alg correct");
};

subtest 'parse_auth_data - rejects too-short data' => sub {
  like(
    dies { Bugzilla::Extension::PasskeyAuth::WebAuthn::_parse_auth_data("short") },
    qr/authData too short/,
    "rejects data shorter than 37 bytes"
  );
};

# -- Registration options generation tests ------------------------------------

subtest 'generate_registration_options' => sub {
  my ($options, $challenge) = Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_registration_options(
    rp_id             => 'example.com',
    rp_name           => 'Example',
    user_id           => 12345,
    user_name         => 'user@example.com',
    user_display_name => 'Test User',
  );

  is($options->{rp}{id}, 'example.com', "RP ID set");
  is($options->{rp}{name}, 'Example', "RP name set");
  is($options->{user}{name}, 'user@example.com', "user name set");
  is($options->{user}{displayName}, 'Test User', "display name set");
  ok(length($challenge) == 32, "challenge is 32 bytes");
  ok(defined $options->{challenge}, "challenge in options");
  is($options->{pubKeyCredParams}[0]{alg}, -7, "ES256 algorithm");
  is($options->{attestation}, 'none', "attestation none");
};

subtest 'generate_registration_options with exclusions' => sub {
  my ($options, $challenge) = Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_registration_options(
    rp_id               => 'example.com',
    user_id             => 1,
    user_name           => 'user@example.com',
    exclude_credentials => ['cred_id_1', 'cred_id_2'],
  );

  is(scalar @{$options->{excludeCredentials}}, 2, "2 excluded credentials");
  is($options->{excludeCredentials}[0]{type}, 'public-key', "type is public-key");
};

# -- Authentication options generation tests ----------------------------------

subtest 'generate_authentication_options' => sub {
  my ($options, $challenge) = Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(
    rp_id => 'example.com',
  );

  is($options->{rpId}, 'example.com', "RP ID set");
  ok(defined $options->{challenge}, "challenge present");
  ok(length($challenge) == 32, "challenge is 32 bytes");
  is($options->{userVerification}, 'preferred', "UV preferred");
  ok(!exists $options->{allowCredentials}, "no allowCredentials for discoverable flow");
};

# -- Full registration + authentication round-trip ----------------------------

subtest 'full WebAuthn registration and authentication round-trip' => sub {
  my $rp_id  = 'example.com';
  my $origin = 'https://example.com';

  # Generate a simulated authenticator keypair
  my $auth_pk = Crypt::PK::ECC->new();
  $auth_pk->generate_key('nistp256');

  # --- Registration ---
  my ($reg_options, $reg_challenge) =
    Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_registration_options(
      rp_id     => $rp_id,
      user_id   => 42,
      user_name => 'test@example.com',
    );

  # Simulate authenticator creating a credential
  my $credential_id = random_bytes(32);
  my $pub_raw = $auth_pk->export_key_raw('public');
  my $x = substr($pub_raw, 1, 32);
  my $y = substr($pub_raw, 33, 32);

  my $cose_key = {1 => 2, 3 => -7, -1 => 1, -2 => $x, -3 => $y};
  my $cose_cbor = CBOR::PP::encode($cose_key);

  my $rp_id_hash = sha256($rp_id);
  my $reg_auth_data = $rp_id_hash
    . pack('C', 0x41)  # UP + AT flags
    . pack('N', 0)     # sign count
    . ("\x00" x 16)    # aaguid
    . pack('n', length($credential_id))
    . $credential_id
    . $cose_cbor;

  my $attestation_obj = CBOR::PP::encode({
    fmt      => 'none',
    attStmt  => {},
    authData => $reg_auth_data,
  });

  my $reg_client_data = JSON::XS::encode_json({
    type      => 'webauthn.create',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($reg_challenge),
    origin    => $origin,
  });

  my $reg_result = Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_registration(
    client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($reg_client_data),
    attestation_object => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($attestation_obj),
    expected_challenge => $reg_challenge,
    expected_origin    => $origin,
    expected_rp_id     => $rp_id,
  );

  ok(defined $reg_result->{credential_id}, "registration returned credential_id");
  ok(defined $reg_result->{public_key}, "registration returned public_key");
  like($reg_result->{public_key}, qr/BEGIN PUBLIC KEY/, "public key is PEM");

  # --- Authentication ---
  my ($auth_options, $auth_challenge) =
    Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(
      rp_id => $rp_id,
    );

  # Simulate authenticator signing the assertion
  my $auth_auth_data = $rp_id_hash
    . pack('C', 0x01)  # UP flag
    . pack('N', 1);    # sign count = 1

  my $auth_client_data = JSON::XS::encode_json({
    type      => 'webauthn.get',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_challenge),
    origin    => $origin,
  });

  my $client_data_hash = sha256($auth_client_data);
  my $signed_data = $auth_auth_data . $client_data_hash;
  my $signature = $auth_pk->sign_message($signed_data, 'SHA256');

  my $auth_result = Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
    credential_id      => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($credential_id),
    client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_client_data),
    authenticator_data => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_auth_data),
    signature          => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($signature),
    expected_challenge => $auth_challenge,
    expected_origin    => $origin,
    expected_rp_id     => $rp_id,
    stored_public_key  => $reg_result->{public_key},
    stored_sign_count  => 0,
  );

  is($auth_result->{sign_count}, 1, "authentication returned updated sign count");
};

# -- Verification failure tests -----------------------------------------------

subtest 'authentication rejects wrong origin' => sub {
  my $rp_id  = 'example.com';
  my $origin = 'https://example.com';

  my $auth_pk = Crypt::PK::ECC->new();
  $auth_pk->generate_key('nistp256');

  my (undef, $challenge) =
    Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(rp_id => $rp_id);

  my $rp_id_hash = sha256($rp_id);
  my $auth_data = $rp_id_hash . pack('C', 0x01) . pack('N', 1);

  my $client_data = JSON::XS::encode_json({
    type      => 'webauthn.get',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($challenge),
    origin    => 'https://evil.com',  # wrong origin
  });

  my $signed_data = $auth_data . sha256($client_data);
  my $signature = $auth_pk->sign_message($signed_data, 'SHA256');

  my $pem = $auth_pk->export_key_pem('public');

  like(
    dies {
      Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
        credential_id      => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url(random_bytes(32)),
        client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($client_data),
        authenticator_data => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_data),
        signature          => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($signature),
        expected_challenge => $challenge,
        expected_origin    => $origin,
        expected_rp_id     => $rp_id,
        stored_public_key  => $pem,
        stored_sign_count  => 0,
      )
    },
    qr/origin mismatch/,
    "rejects wrong origin"
  );
};

subtest 'authentication rejects wrong challenge' => sub {
  my $rp_id  = 'example.com';
  my $origin = 'https://example.com';

  my $auth_pk = Crypt::PK::ECC->new();
  $auth_pk->generate_key('nistp256');

  my $real_challenge = random_bytes(32);
  my $wrong_challenge = random_bytes(32);

  my $rp_id_hash = sha256($rp_id);
  my $auth_data = $rp_id_hash . pack('C', 0x01) . pack('N', 1);

  my $client_data = JSON::XS::encode_json({
    type      => 'webauthn.get',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($wrong_challenge),
    origin    => $origin,
  });

  my $signed_data = $auth_data . sha256($client_data);
  my $signature = $auth_pk->sign_message($signed_data, 'SHA256');
  my $pem = $auth_pk->export_key_pem('public');

  like(
    dies {
      Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
        credential_id      => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url(random_bytes(32)),
        client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($client_data),
        authenticator_data => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_data),
        signature          => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($signature),
        expected_challenge => $real_challenge,
        expected_origin    => $origin,
        expected_rp_id     => $rp_id,
        stored_public_key  => $pem,
        stored_sign_count  => 0,
      )
    },
    qr/challenge mismatch/,
    "rejects wrong challenge"
  );
};

subtest 'authentication rejects invalid signature' => sub {
  my $rp_id  = 'example.com';
  my $origin = 'https://example.com';

  my $real_pk = Crypt::PK::ECC->new();
  $real_pk->generate_key('nistp256');

  my $wrong_pk = Crypt::PK::ECC->new();
  $wrong_pk->generate_key('nistp256');

  my (undef, $challenge) =
    Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(rp_id => $rp_id);

  my $rp_id_hash = sha256($rp_id);
  my $auth_data = $rp_id_hash . pack('C', 0x01) . pack('N', 1);

  my $client_data = JSON::XS::encode_json({
    type      => 'webauthn.get',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($challenge),
    origin    => $origin,
  });

  # Sign with the WRONG key
  my $signed_data = $auth_data . sha256($client_data);
  my $signature = $wrong_pk->sign_message($signed_data, 'SHA256');

  # But verify against the REAL key
  my $pem = $real_pk->export_key_pem('public');

  like(
    dies {
      Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
        credential_id      => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url(random_bytes(32)),
        client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($client_data),
        authenticator_data => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_data),
        signature          => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($signature),
        expected_challenge => $challenge,
        expected_origin    => $origin,
        expected_rp_id     => $rp_id,
        stored_public_key  => $pem,
        stored_sign_count  => 0,
      )
    },
    qr/invalid signature/,
    "rejects signature from wrong key"
  );
};

subtest 'authentication rejects sign count rollback' => sub {
  my $rp_id  = 'example.com';
  my $origin = 'https://example.com';

  my $auth_pk = Crypt::PK::ECC->new();
  $auth_pk->generate_key('nistp256');

  my (undef, $challenge) =
    Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(rp_id => $rp_id);

  my $rp_id_hash = sha256($rp_id);
  # Authenticator reports sign_count = 5, but stored is 10
  my $auth_data = $rp_id_hash . pack('C', 0x01) . pack('N', 5);

  my $client_data = JSON::XS::encode_json({
    type      => 'webauthn.get',
    challenge => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($challenge),
    origin    => $origin,
  });

  my $signed_data = $auth_data . sha256($client_data);
  my $signature = $auth_pk->sign_message($signed_data, 'SHA256');
  my $pem = $auth_pk->export_key_pem('public');

  like(
    dies {
      Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
        credential_id      => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url(random_bytes(32)),
        client_data_json   => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($client_data),
        authenticator_data => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($auth_data),
        signature          => Bugzilla::Extension::PasskeyAuth::WebAuthn::_encode_b64url($signature),
        expected_challenge => $challenge,
        expected_origin    => $origin,
        expected_rp_id     => $rp_id,
        stored_public_key  => $pem,
        stored_sign_count  => 10,
      )
    },
    qr/cloned authenticator/,
    "rejects sign count rollback (possible clone)"
  );
};

done_testing();
