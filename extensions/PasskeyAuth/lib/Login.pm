# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::PasskeyAuth::Login;

use 5.10.1;
use strict;
use warnings;

use base qw(Bugzilla::Auth::Login);

use Bugzilla::Constants qw(AUTH_NODATA AUTH_ERROR USAGE_MODE_BROWSER);
use Bugzilla::Error;

use constant requires_verification   => 1;
use constant is_automatic            => 1;
use constant user_can_create_account => 0;
use constant auth_method             => 'Passkey';

sub get_login_info {
  my ($self) = @_;
  my $passkey_user_id = Bugzilla->request_cache->{passkey_user_id};

  return {failure => AUTH_NODATA} unless $passkey_user_id;

  my $user = Bugzilla::User->new($passkey_user_id);
  return {failure => AUTH_ERROR, error => 'passkey_invalid_user'}
    unless $user;

  return {
    username    => $user->login,
    user_id     => $user->id,
    passkey_auth => 1,
  };
}

sub fail_nodata {
  my ($self) = @_;
  my $cgi    = Bugzilla->cgi;

  ThrowUserError('login_required') if Bugzilla->usage_mode != USAGE_MODE_BROWSER;

  my $template = Bugzilla->template;
  print $cgi->header();
  $template->process("account/auth/login.html.tmpl",
    {target => $cgi->url(-relative => 1)})
    or ThrowTemplateError($template->error());
  exit;
}

1;
