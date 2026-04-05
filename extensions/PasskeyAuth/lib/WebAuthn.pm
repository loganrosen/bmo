# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::PasskeyAuth::WebAuthn;

use 5.10.1;
use strict;
use warnings;

use CBOR::PP   ();
use Crypt::PRNG qw(random_bytes);
use Crypt::PK::ECC;
use Crypt::Digest::SHA256 qw(sha256);
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS     ();

use Bugzilla::Error;

# ES256 = ECDSA w/ P-256 and SHA-256 (COSE algorithm -7)
use constant COSE_ALG_ES256 => -7;

# -- Base64url helpers --------------------------------------------------------

sub _encode_b64url {
  my ($data) = @_;
  my $b64 = encode_base64($data, '');
  $b64 =~ tr[+/=][-_]d;
  return $b64;
}

sub _decode_b64url {
  my ($text) = @_;
  $text =~ tr[-_][+/];
  $text .= '=' x ((4 - length($text) % 4) % 4);
  return decode_base64($text);
}

# -- Registration (attestation) -----------------------------------------------

sub generate_registration_options {
  my (%args) = @_;

  my $rp_id   = $args{rp_id}   || ThrowCodeError('passkey_missing_param', {param => 'rp_id'});
  my $rp_name = $args{rp_name} || $rp_id;
  my $user_id   = $args{user_id}   || ThrowCodeError('passkey_missing_param', {param => 'user_id'});
  my $user_name = $args{user_name} || ThrowCodeError('passkey_missing_param', {param => 'user_name'});
  my $user_display_name = $args{user_display_name} || $user_name;
  my $exclude_credentials = $args{exclude_credentials} || [];

  my $challenge = random_bytes(32);

  my $options = {
    rp      => {id => $rp_id, name => $rp_name},
    user    => {
      id          => _encode_b64url(pack('N', $user_id)),
      name        => $user_name,
      displayName => $user_display_name,
    },
    challenge               => _encode_b64url($challenge),
    pubKeyCredParams        => [{type => 'public-key', alg => COSE_ALG_ES256}],
    timeout                 => 60_000,
    attestation             => 'none',
    authenticatorSelection  => {
      userVerification => 'preferred',
      residentKey      => 'preferred',
    },
  };

  if (@$exclude_credentials) {
    $options->{excludeCredentials} = [
      map { {type => 'public-key', id => $_} } @$exclude_credentials
    ];
  }

  return ($options, $challenge);
}

sub verify_registration {
  my (%args) = @_;

  my $client_data_json_b64 = $args{client_data_json}
    || ThrowCodeError('passkey_missing_param', {param => 'client_data_json'});
  my $attestation_object_b64 = $args{attestation_object}
    || ThrowCodeError('passkey_missing_param', {param => 'attestation_object'});
  my $expected_challenge = $args{expected_challenge}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_challenge'});
  my $expected_origin = $args{expected_origin}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_origin'});
  my $expected_rp_id = $args{expected_rp_id}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_rp_id'});

  # 1. Decode and verify clientDataJSON
  my $client_data_json = _decode_b64url($client_data_json_b64);
  my $client_data = JSON::XS::decode_json($client_data_json);

  ThrowUserError('passkey_verification_failed', {reason => 'type mismatch'})
    unless $client_data->{type} eq 'webauthn.create';

  my $challenge_b64url = _encode_b64url($expected_challenge);
  ThrowUserError('passkey_verification_failed', {reason => 'challenge mismatch'})
    unless $client_data->{challenge} eq $challenge_b64url;

  ThrowUserError('passkey_verification_failed', {reason => 'origin mismatch'})
    unless $client_data->{origin} eq $expected_origin;

  # 2. Decode attestation object (CBOR)
  my $attestation_object_raw = _decode_b64url($attestation_object_b64);
  my $attestation = CBOR::PP::decode($attestation_object_raw);

  my $auth_data_raw = $attestation->{authData};
  ThrowUserError('passkey_verification_failed', {reason => 'missing authData'})
    unless $auth_data_raw;

  # 3. Parse authenticator data
  my $auth_data = _parse_auth_data($auth_data_raw);

  # Verify RP ID hash
  my $expected_rp_id_hash = sha256($expected_rp_id);
  ThrowUserError('passkey_verification_failed', {reason => 'rpIdHash mismatch'})
    unless $auth_data->{rp_id_hash} eq $expected_rp_id_hash;

  # Verify user-present flag
  ThrowUserError('passkey_verification_failed', {reason => 'user not present'})
    unless $auth_data->{flags} & 0x01;

  # 4. Extract credential public key from attested credential data
  ThrowUserError('passkey_verification_failed', {reason => 'no attested credential'})
    unless $auth_data->{attested_credential};

  my $credential_id_raw = $auth_data->{attested_credential}{credential_id};
  my $cose_key = $auth_data->{attested_credential}{public_key};

  # 5. Convert COSE key to PEM
  my $pem = _cose_key_to_pem($cose_key);

  return {
    credential_id => _encode_b64url($credential_id_raw),
    public_key    => $pem,
    sign_count    => $auth_data->{sign_count},
  };
}

# -- Authentication (assertion) -----------------------------------------------

sub generate_authentication_options {
  my (%args) = @_;

  my $rp_id = $args{rp_id} || ThrowCodeError('passkey_missing_param', {param => 'rp_id'});
  my $allow_credentials = $args{allow_credentials} || [];

  my $challenge = random_bytes(32);

  my $options = {
    challenge        => _encode_b64url($challenge),
    rpId             => $rp_id,
    timeout          => 60_000,
    userVerification => 'preferred',
  };

  if (@$allow_credentials) {
    $options->{allowCredentials} = [
      map { {type => 'public-key', id => $_} } @$allow_credentials
    ];
  }

  return ($options, $challenge);
}

sub verify_authentication {
  my (%args) = @_;

  my $credential_id_b64    = $args{credential_id}
    || ThrowCodeError('passkey_missing_param', {param => 'credential_id'});
  my $client_data_json_b64 = $args{client_data_json}
    || ThrowCodeError('passkey_missing_param', {param => 'client_data_json'});
  my $auth_data_b64        = $args{authenticator_data}
    || ThrowCodeError('passkey_missing_param', {param => 'authenticator_data'});
  my $signature_b64        = $args{signature}
    || ThrowCodeError('passkey_missing_param', {param => 'signature'});
  my $expected_challenge    = $args{expected_challenge}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_challenge'});
  my $expected_origin       = $args{expected_origin}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_origin'});
  my $expected_rp_id        = $args{expected_rp_id}
    || ThrowCodeError('passkey_missing_param', {param => 'expected_rp_id'});
  my $stored_public_key_pem = $args{stored_public_key}
    || ThrowCodeError('passkey_missing_param', {param => 'stored_public_key'});
  my $stored_sign_count     = $args{stored_sign_count} // 0;

  # 1. Decode and verify clientDataJSON
  my $client_data_json = _decode_b64url($client_data_json_b64);
  my $client_data = JSON::XS::decode_json($client_data_json);

  ThrowUserError('passkey_verification_failed', {reason => 'type mismatch'})
    unless $client_data->{type} eq 'webauthn.get';

  my $challenge_b64url = _encode_b64url($expected_challenge);
  ThrowUserError('passkey_verification_failed', {reason => 'challenge mismatch'})
    unless $client_data->{challenge} eq $challenge_b64url;

  ThrowUserError('passkey_verification_failed', {reason => 'origin mismatch'})
    unless $client_data->{origin} eq $expected_origin;

  # 2. Parse authenticator data
  my $auth_data_raw = _decode_b64url($auth_data_b64);
  my $auth_data = _parse_auth_data($auth_data_raw);

  # Verify RP ID hash
  my $expected_rp_id_hash = sha256($expected_rp_id);
  ThrowUserError('passkey_verification_failed', {reason => 'rpIdHash mismatch'})
    unless $auth_data->{rp_id_hash} eq $expected_rp_id_hash;

  # Verify user-present flag
  ThrowUserError('passkey_verification_failed', {reason => 'user not present'})
    unless $auth_data->{flags} & 0x01;

  # 3. Verify signature
  # signature = sign(authData || sha256(clientDataJSON))
  my $client_data_hash = sha256($client_data_json);
  my $signed_data = $auth_data_raw . $client_data_hash;

  my $signature = _decode_b64url($signature_b64);

  my $pk = Crypt::PK::ECC->new(\$stored_public_key_pem);
  my $valid = $pk->verify_message($signature, $signed_data, 'SHA256');

  ThrowUserError('passkey_verification_failed', {reason => 'invalid signature'})
    unless $valid;

  # 4. Check sign count (clone detection)
  # If stored count is non-zero, the authenticator supports counters,
  # so we require the new count to be strictly greater.
  if ($stored_sign_count > 0 && $auth_data->{sign_count} <= $stored_sign_count) {
    ThrowUserError('passkey_verification_failed', {reason => 'possible cloned authenticator'});
  }

  return {
    sign_count => $auth_data->{sign_count},
  };
}

# -- Internal helpers ---------------------------------------------------------

sub _parse_auth_data {
  my ($raw) = @_;
  my $len = length($raw);

  ThrowUserError('passkey_verification_failed', {reason => 'authData too short'})
    if $len < 37;

  my $rp_id_hash = substr($raw, 0, 32);
  my $flags      = unpack('C', substr($raw, 32, 1));
  my $sign_count = unpack('N', substr($raw, 33, 4));

  my $result = {
    rp_id_hash => $rp_id_hash,
    flags      => $flags,
    sign_count => $sign_count,
  };

  # Bit 6: attested credential data included
  if ($flags & 0x40) {
    ThrowUserError('passkey_verification_failed', {reason => 'authData too short for credential'})
      if $len < 55;

    my $aaguid = substr($raw, 37, 16);
    my $cred_id_len = unpack('n', substr($raw, 53, 2));

    ThrowUserError('passkey_verification_failed', {reason => 'authData truncated'})
      if $len < 55 + $cred_id_len;

    my $credential_id = substr($raw, 55, $cred_id_len);

    # The rest is CBOR-encoded COSE public key
    my $cose_key_raw = substr($raw, 55 + $cred_id_len);
    my $cose_key = CBOR::PP::decode($cose_key_raw);

    $result->{attested_credential} = {
      aaguid        => $aaguid,
      credential_id => $credential_id,
      public_key    => $cose_key,
    };
  }

  return $result;
}

sub _cose_key_to_pem {
  my ($cose_key) = @_;

  # COSE key map labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
  my $kty = $cose_key->{1};
  my $alg = $cose_key->{3};

  # EC2 key type = 2, ES256 algorithm = -7
  ThrowUserError('passkey_verification_failed', {reason => 'unsupported key type'})
    unless $kty == 2 && $alg == COSE_ALG_ES256;

  my $crv = $cose_key->{-1};  # P-256 = 1
  ThrowUserError('passkey_verification_failed', {reason => 'unsupported curve'})
    unless $crv == 1;

  my $x = $cose_key->{-2};
  my $y = $cose_key->{-3};

  ThrowUserError('passkey_verification_failed', {reason => 'missing key coordinates'})
    unless defined $x && defined $y;

  # Build uncompressed EC point: 0x04 || x || y
  my $pub_point = "\x04" . $x . $y;

  # Import into CryptX ECC and export as PEM
  my $pk = Crypt::PK::ECC->new();
  $pk->import_key_raw($pub_point, 'nistp256');
  return $pk->export_key_pem('public');
}

1;
