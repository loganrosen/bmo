# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::PasskeyAuth::WebService;

use 5.10.1;
use strict;
use warnings;

use base qw(Bugzilla::WebService);

use Bugzilla::Error;
use Bugzilla::Token qw(issue_short_lived_session_token
  set_token_extra_data get_token_extra_data delete_token);
use Bugzilla::Extension::PasskeyAuth::WebAuthn;
use Bugzilla::Util qw(datetime_from remote_ip);
use DateTime;

use constant PUBLIC_METHODS => qw(
  login_begin
  register_begin
  register_complete
  list_credentials
  delete_credential
);

use constant LOGIN_EXEMPT => {login_begin => 1};

sub rest_resources {
  return [
    qr{^/passkey/login/begin$},
    {GET => {method => 'login_begin'}},

    qr{^/passkey/register/begin$},
    {POST => {method => 'register_begin'}},

    qr{^/passkey/register/complete$},
    {POST => {method => 'register_complete'}},

    qr{^/passkey/credentials$},
    {GET => {method => 'list_credentials'}},

    qr{^/passkey/credentials/(\d+)$},
    {DELETE => {method => 'delete_credential', params => {id => qr/^(\d+)$/}}},
  ];
}

sub _rp_id {
  my $urlbase = Bugzilla->localconfig->urlbase;
  my ($host)  = $urlbase =~ m{^https?://([^/:]+)};
  return $host;
}

sub _origin {
  my $urlbase = Bugzilla->localconfig->urlbase;
  $urlbase =~ s{/$}{};
  return $urlbase;
}

# GET /rest/passkey/login/begin
sub login_begin {
  my ($self) = @_;

  # Rate-limit unauthenticated challenge generation
  Bugzilla->check_rate_limit('passkey', remote_ip());

  my $rp_id = _rp_id();
  my ($options, $challenge)
    = Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_authentication_options(
      rp_id => $rp_id,
    );

  # Store challenge in a short-lived token
  my $token = issue_short_lived_session_token('passkey_login');
  set_token_extra_data($token, {challenge => $challenge});

  return {options => $options, passkey_token => $token};
}

# POST /rest/passkey/register/begin
sub register_begin {
  my ($self, $params) = @_;

  my $user = Bugzilla->login(Bugzilla::Constants::LOGIN_REQUIRED);

  my $name = $params->{name};
  ThrowUserError('passkey_name_required') unless $name && $name =~ /\S/;

  # Limit passkeys per user
  my $dbh = Bugzilla->dbh;
  my ($count) = $dbh->selectrow_array(
    'SELECT COUNT(*) FROM passkeys WHERE user_id = ?', undef, $user->id);
  ThrowUserError('passkey_limit_exceeded') if $count >= 50;

  # Fetch existing credential IDs to exclude
  my $existing = $dbh->selectcol_arrayref(
    'SELECT credential_id FROM passkeys WHERE user_id = ?',
    undef, $user->id);

  my $rp_id = _rp_id();
  my ($options, $challenge)
    = Bugzilla::Extension::PasskeyAuth::WebAuthn::generate_registration_options(
      rp_id             => $rp_id,
      rp_name           => 'Bugzilla',
      user_id           => $user->id,
      user_name         => $user->login,
      user_display_name => $user->name || $user->login,
      exclude_credentials => $existing,
    );

  my $token = issue_short_lived_session_token('passkey_register');
  set_token_extra_data($token, {challenge => $challenge, name => $name});

  return {options => $options, passkey_token => $token};
}

# POST /rest/passkey/register/complete
sub register_complete {
  my ($self, $params) = @_;

  my $user = Bugzilla->login(Bugzilla::Constants::LOGIN_REQUIRED);

  my $token_value        = $params->{passkey_token}
    || ThrowUserError('passkey_missing_token');
  my $client_data_json   = $params->{clientDataJSON}
    || ThrowUserError('passkey_missing_response');
  my $attestation_object = $params->{attestationObject}
    || ThrowUserError('passkey_missing_response');

  # Retrieve and validate the stored challenge
  my $token_data = get_token_extra_data($token_value);
  ThrowUserError('passkey_invalid_token')
    unless $token_data && $token_data->{challenge};

  my $result = Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_registration(
    client_data_json   => $client_data_json,
    attestation_object => $attestation_object,
    expected_challenge => $token_data->{challenge},
    expected_origin    => _origin(),
    expected_rp_id     => _rp_id(),
  );

  # Token verified — consume it now
  delete_token($token_value);

  # Store the credential
  my $dbh = Bugzilla->dbh;
  $dbh->do(
    'INSERT INTO passkeys (user_id, credential_id, public_key, name, sign_count, created_at)
     VALUES (?, ?, ?, ?, ?, NOW())',
    undef,
    $user->id,
    $result->{credential_id},
    $result->{public_key},
    $token_data->{name},
    $result->{sign_count},
  );

  return {success => 1};
}

# GET /rest/passkey/credentials
sub list_credentials {
  my ($self) = @_;

  my $user = Bugzilla->login(Bugzilla::Constants::LOGIN_REQUIRED);
  my $dbh  = Bugzilla->dbh;

  my $rows = $dbh->selectall_arrayref(
    'SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at',
    {Slice => {}},
    $user->id);

  return {credentials => $rows};
}

# DELETE /rest/passkey/credentials/:id
sub delete_credential {
  my ($self, $params) = @_;

  my $user = Bugzilla->login(Bugzilla::Constants::LOGIN_REQUIRED);
  my $id   = $params->{id};

  ThrowUserError('passkey_invalid_id') unless $id && $id =~ /^\d+$/;

  my $dbh = Bugzilla->dbh;
  my ($owner) = $dbh->selectrow_array(
    'SELECT user_id FROM passkeys WHERE id = ?', undef, $id);

  ThrowUserError('passkey_not_found') unless $owner;
  ThrowUserError('passkey_not_owner')  unless $owner == $user->id;

  $dbh->do('DELETE FROM passkeys WHERE id = ?', undef, $id);

  return {success => 1};
}

1;
