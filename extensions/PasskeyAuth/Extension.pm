# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::PasskeyAuth;

use 5.10.1;
use strict;
use warnings;

use parent qw(Bugzilla::Extension);

use List::Util qw(first);

our $VERSION = '0.01';

sub auth_login_methods {
  my ($self, $args) = @_;
  my $modules = $args->{'modules'};
  if (exists $modules->{'PasskeyAuth'}) {
    $modules->{'PasskeyAuth'} = 'Bugzilla/Extension/PasskeyAuth/Login.pm';
  }
}

sub auth_verify_methods {
  my ($self, $args) = @_;
  my $modules = $args->{'modules'};
  if (exists $modules->{'PasskeyAuth'}) {
    $modules->{'PasskeyAuth'} = 'Bugzilla/Extension/PasskeyAuth/Verify.pm';
  }
}

sub config_modify_panels {
  my ($self, $args) = @_;
  my $auth_panel_params = $args->{panels}{auth}{params};

  my $user_info_class
    = first { $_->{name} eq 'user_info_class' } @$auth_panel_params;
  if ($user_info_class) {
    push @{$user_info_class->{choices}},
      "PasskeyAuth,CGI",
      "PasskeyAuth,OAuth2,CGI",
      "PasskeyAuth,GitHubAuth,CGI",
      "PasskeyAuth,GitHubAuth,OAuth2,CGI";
  }

  my $user_verify_class
    = first { $_->{name} eq 'user_verify_class' } @$auth_panel_params;
  if ($user_verify_class) {
    unshift @{$user_verify_class->{choices}}, "PasskeyAuth";
  }
}

sub db_schema_abstract_schema {
  my ($self, $args) = @_;
  $args->{schema}->{passkeys} = {
    FIELDS => [
      id => {TYPE => 'INTSERIAL', NOTNULL => 1, PRIMARYKEY => 1},
      user_id => {
        TYPE       => 'INT3',
        NOTNULL    => 1,
        REFERENCES => {TABLE => 'profiles', COLUMN => 'userid', DELETE => 'CASCADE'},
      },
      credential_id => {TYPE => 'VARCHAR(512)', NOTNULL => 1},
      public_key    => {TYPE => 'MEDIUMTEXT',   NOTNULL => 1},
      name          => {TYPE => 'VARCHAR(255)', NOTNULL => 1},
      sign_count    => {TYPE => 'INT4',         NOTNULL => 1, DEFAULT => 0},
      created_at    => {TYPE => 'DATETIME',     NOTNULL => 1},
      last_used_at  => {TYPE => 'DATETIME',     NOTNULL => 0},
    ],
    INDEXES => [
      passkeys_credential_id_idx => {FIELDS => ['credential_id'], TYPE => 'UNIQUE'},
      passkeys_user_id_idx       => ['user_id'],
    ],
  };
}

sub webservice {
  my ($self, $args) = @_;
  $args->{dispatch}->{PasskeyAuth} = 'Bugzilla::Extension::PasskeyAuth::WebService';
}

sub user_preferences {
  my ($self, $args) = @_;
  return unless $args->{current_tab} eq 'passkeys';
  ${$args->{handled}} = 1;
}

__PACKAGE__->NAME;
