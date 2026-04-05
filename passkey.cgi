#!/usr/bin/env perl
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

use 5.10.1;
use strict;
use warnings;

use lib qw(. lib local/lib/perl5);

use Bugzilla;
use Bugzilla::Constants;
use Bugzilla::Error;
use Bugzilla::Util qw(remote_ip);
use Bugzilla::Token qw(get_token_extra_data delete_token);
use JSON::XS ();

BEGIN { Bugzilla->extensions }

use Bugzilla::Extension::PasskeyAuth::WebAuthn;

my $cgi = Bugzilla->cgi;

# Only accept POST requests
ThrowCodeError('passkey_invalid_request')
  unless lc($cgi->request_method) eq 'post';

# Read the JSON body
my $body = $cgi->param('POSTDATA') || $cgi->param('data');
ThrowUserError('passkey_missing_response') unless $body;

my $data = eval { JSON::XS::decode_json($body) };
ThrowUserError('passkey_missing_response') if $@ || !$data;

my $token_value      = $data->{passkey_token}
  || ThrowUserError('passkey_missing_token');
my $credential_id    = $data->{credentialId}
  || ThrowUserError('passkey_missing_response');
my $client_data_json = $data->{clientDataJSON}
  || ThrowUserError('passkey_missing_response');
my $authenticator_data = $data->{authenticatorData}
  || ThrowUserError('passkey_missing_response');
my $signature        = $data->{signature}
  || ThrowUserError('passkey_missing_response');

# Retrieve the stored challenge
my $token_data = get_token_extra_data($token_value);
unless ($token_data && $token_data->{challenge}) {
  Bugzilla->check_rate_limit('passkey', remote_ip());
  ThrowUserError('passkey_invalid_token');
}

# Look up the credential in the database
my $dbh = Bugzilla->dbh;
my $credential = $dbh->selectrow_hashref(
  'SELECT id, user_id, credential_id, public_key, sign_count
   FROM passkeys WHERE credential_id = ?',
  undef, $credential_id);

unless ($credential) {
  Bugzilla->check_rate_limit('passkey', remote_ip());
  ThrowUserError('passkey_verification_failed', {reason => 'unknown credential'});
}

# Determine origin and RP ID from urlbase
my $urlbase = Bugzilla->localconfig->urlbase;
my ($rp_host) = $urlbase =~ m{^https?://([^/:]+)};
(my $origin = $urlbase) =~ s{/$}{};

# Verify the assertion
my $result = Bugzilla::Extension::PasskeyAuth::WebAuthn::verify_authentication(
  credential_id      => $credential_id,
  client_data_json   => $client_data_json,
  authenticator_data => $authenticator_data,
  signature          => $signature,
  expected_challenge => $token_data->{challenge},
  expected_origin    => $origin,
  expected_rp_id     => $rp_host,
  stored_public_key  => $credential->{public_key},
  stored_sign_count  => $credential->{sign_count},
);

# Token verified successfully — consume it now
delete_token($token_value);

# Update sign count and last_used_at
$dbh->do(
  'UPDATE passkeys SET sign_count = ?, last_used_at = NOW() WHERE id = ?',
  undef, $result->{sign_count}, $credential->{id});

# Set request cache so PasskeyAuth::Login picks up the authenticated user
Bugzilla->request_cache->{passkey_user_id} = $credential->{user_id};

# Run through the full auth stack to create the session
my $user = Bugzilla->login(LOGIN_REQUIRED);

# Determine redirect target
my $target = $data->{target_uri} || $urlbase;

# Strict origin validation to prevent open redirects
my ($target_origin) = $target =~ m{^(https?://[^/]+)};
ThrowCodeError('passkey_invalid_request')
  unless $target_origin && $target_origin eq $origin;

# Return JSON response (the JS will handle the redirect)
print $cgi->header('application/json');
print JSON::XS::encode_json({
  success     => 1,
  redirect_to => $target,
});
